package com.example.userauthentication.service;

import com.example.userauthentication.model.AuditLog;
import com.example.userauthentication.model.User;
import com.example.userauthentication.repository.AuditLogRepository;
import com.example.userauthentication.repository.UserRepository;
import com.example.userauthentication.security.JwtTokenService;
import com.example.userauthentication.security.RateLimitingService;
import io.micrometer.core.annotation.Timed;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service class for authentication operations.
 * Handles login functionality with failed attempt tracking, account locking mechanisms,
 * JWT token generation, and comprehensive metrics integration.
 * 
 * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
 */
@Service
@Transactional
public class AuthenticationService {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationService.class);
    
    // Account locking configuration
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int ACCOUNT_LOCK_DURATION_MINUTES = 30;
    
    // Rate limiting configuration
    private static final int LOGIN_RATE_LIMIT_ATTEMPTS = 10;
    private static final int LOGIN_RATE_LIMIT_WINDOW_MINUTES = 15;

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenService jwtTokenService;
    private final RateLimitingService rateLimitingService;
    
    // Metrics
    private final Counter loginAttempts;
    private final Counter loginSuccesses;
    private final Counter loginFailures;
    private final Counter accountLockouts;
    private final Counter rateLimitViolations;
    private final Timer authenticationTimer;

    public AuthenticationService(UserRepository userRepository,
                               AuditLogRepository auditLogRepository,
                               PasswordEncoder passwordEncoder,
                               JwtTokenService jwtTokenService,
                               RateLimitingService rateLimitingService,
                               MeterRegistry meterRegistry) {
        this.userRepository = userRepository;
        this.auditLogRepository = auditLogRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenService = jwtTokenService;
        this.rateLimitingService = rateLimitingService;
        
        // Initialize metrics
        this.loginAttempts = Counter.builder("auth.login.attempts")
                .description("Total number of login attempts")
                .register(meterRegistry);
        this.loginSuccesses = Counter.builder("auth.login.successes")
                .description("Total number of successful logins")
                .register(meterRegistry);
        this.loginFailures = Counter.builder("auth.login.failures")
                .description("Total number of failed logins")
                .register(meterRegistry);
        this.accountLockouts = Counter.builder("auth.account.lockouts")
                .description("Total number of account lockouts")
                .register(meterRegistry);
        this.rateLimitViolations = Counter.builder("auth.rate.limit.violations")
                .description("Total number of rate limit violations")
                .register(meterRegistry);
        this.authenticationTimer = Timer.builder("auth.login.duration")
                .description("Time taken to process login attempts")
                .register(meterRegistry);
    }

    /**
     * Authenticates a user with email and password.
     * Implements comprehensive security measures including rate limiting,
     * failed attempt tracking, and account locking.
     * 
     * @param email the user's email address
     * @param password the user's plain text password
     * @param ipAddress the client's IP address for audit logging
     * @param userAgent the client's user agent for audit logging
     * @return AuthenticationResult containing success status, JWT tokens, and user info
     */
    @Timed(value = "auth.login.processing.time", description = "Time taken to process login request")
    public AuthenticationResult authenticate(String email, String password, String ipAddress, String userAgent) {
        loginAttempts.increment();
        
        Timer.Sample sample = Timer.start();
        try {
            logger.info("Authentication attempt for email: {} from IP: {}", email, ipAddress);
            
            // Input validation
            if (email == null || email.trim().isEmpty()) {
                return handleAuthenticationFailure(null, "Email is required", 
                                                 ipAddress, userAgent, "INVALID_INPUT");
            }
            
            if (password == null || password.isEmpty()) {
                return handleAuthenticationFailure(null, "Password is required", 
                                                 ipAddress, userAgent, "INVALID_INPUT");
            }
            
            // Rate limiting check
            String rateLimitKey = "login:" + ipAddress + ":" + email;
            if (!rateLimitingService.isAllowed(rateLimitKey, LOGIN_RATE_LIMIT_ATTEMPTS, LOGIN_RATE_LIMIT_WINDOW_MINUTES)) {
                rateLimitViolations.increment();
                logger.warn("Rate limit exceeded for login attempt. Email: {}, IP: {}", email, ipAddress);
                return handleAuthenticationFailure(null, "Too many login attempts. Please try again later.", 
                                                 ipAddress, userAgent, "RATE_LIMIT_EXCEEDED");
            }
            
            // Find user by email
            Optional<User> userOptional = userRepository.findByEmail(email);
            if (userOptional.isEmpty()) {
                logger.warn("Login attempt with non-existent email: {}", email);
                return handleAuthenticationFailure(null, "Invalid email or password", 
                                                 ipAddress, userAgent, "INVALID_CREDENTIALS");
            }
            
            User user = userOptional.get();
            
            // Check if account is locked
            if (user.isAccountLocked()) {
                logger.warn("Login attempt on locked account. User ID: {}, Email: {}", user.getId(), email);
                return handleAuthenticationFailure(user.getId(), "Account is temporarily locked due to multiple failed login attempts", 
                                                 ipAddress, userAgent, "ACCOUNT_LOCKED");
            }
            
            // Check if email is verified
            if (!user.getEmailVerified()) {
                logger.warn("Login attempt with unverified email. User ID: {}, Email: {}", user.getId(), email);
                return handleAuthenticationFailure(user.getId(), "Please verify your email address before logging in", 
                                                 ipAddress, userAgent, "EMAIL_NOT_VERIFIED");
            }
            
            // Verify password
            if (!passwordEncoder.matches(password, user.getPasswordHash())) {
                logger.warn("Login attempt with invalid password. User ID: {}, Email: {}", user.getId(), email);
                
                // Increment failed attempts and potentially lock account
                handleFailedLoginAttempt(user, ipAddress, userAgent);
                
                return handleAuthenticationFailure(user.getId(), "Invalid email or password", 
                                                 ipAddress, userAgent, "INVALID_CREDENTIALS");
            }
            
            // Authentication successful
            return handleSuccessfulLogin(user, ipAddress, userAgent);
            
        } catch (Exception e) {
            logger.error("Unexpected error during authentication for email: {}", email, e);
            return handleAuthenticationFailure(null, "Authentication failed due to an internal error", 
                                             ipAddress, userAgent, "INTERNAL_ERROR");
        } finally {
            sample.stop(authenticationTimer);
        }
    }

    /**
     * Handles successful login by updating user data, generating tokens, and logging the event.
     */
    private AuthenticationResult handleSuccessfulLogin(User user, String ipAddress, String userAgent) {
        try {
            // Reset failed login attempts
            if (user.getFailedLoginAttempts() > 0) {
                userRepository.resetFailedLoginAttempts(user.getId());
                user.resetFailedLoginAttempts();
            }
            
            // Update last login timestamp
            LocalDateTime now = LocalDateTime.now();
            userRepository.updateLastLoginTime(user.getId(), now);
            user.updateLastLoginTimestamp();
            
            // Generate JWT tokens
            String accessToken = jwtTokenService.generateToken(user.getId(), user.getEmail());
            String refreshToken = jwtTokenService.generateRefreshToken(user.getId(), user.getEmail());
            
            // Log successful authentication
            AuditLog auditLog = AuditLog.success(
                user.getId(),
                AuditLog.EVENT_USER_LOGIN,
                "User successfully authenticated",
                ipAddress,
                userAgent
            );
            auditLogRepository.save(auditLog);
            
            // Update metrics
            loginSuccesses.increment();
            
            logger.info("Successful authentication for user ID: {}, Email: {}", user.getId(), user.getEmail());
            
            return AuthenticationResult.success(user, accessToken, refreshToken);
            
        } catch (Exception e) {
            logger.error("Error handling successful login for user ID: {}", user.getId(), e);
            return AuthenticationResult.failure("Authentication completed but token generation failed");
        }
    }

    /**
     * Handles failed login attempts by incrementing counters and potentially locking the account.
     */
    private void handleFailedLoginAttempt(User user, String ipAddress, String userAgent) {
        try {
            // Increment failed login attempts
            userRepository.incrementFailedLoginAttempts(user.getId());
            user.incrementFailedLoginAttempts();
            
            // Check if account should be locked
            if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
                LocalDateTime lockUntil = LocalDateTime.now().plusMinutes(ACCOUNT_LOCK_DURATION_MINUTES);
                userRepository.lockUserAccount(user.getId(), lockUntil);
                user.lockAccount(ACCOUNT_LOCK_DURATION_MINUTES);
                
                // Log account lockout
                AuditLog lockoutLog = AuditLog.failure(
                    user.getId(),
                    AuditLog.EVENT_ACCOUNT_LOCKED,
                    String.format("Account locked after %d failed login attempts", MAX_FAILED_ATTEMPTS),
                    ipAddress,
                    userAgent
                );
                auditLogRepository.save(lockoutLog);
                
                accountLockouts.increment();
                logger.warn("Account locked for user ID: {} after {} failed attempts", user.getId(), MAX_FAILED_ATTEMPTS);
            }
            
        } catch (Exception e) {
            logger.error("Error handling failed login attempt for user ID: {}", user.getId(), e);
        }
    }

    /**
     * Handles authentication failures by logging the event and updating metrics.
     */
    private AuthenticationResult handleAuthenticationFailure(Long userId, String message, 
                                                           String ipAddress, String userAgent, String reason) {
        try {
            // Log failed authentication
            AuditLog auditLog = AuditLog.failure(
                userId,
                AuditLog.EVENT_USER_LOGIN,
                String.format("Authentication failed: %s", reason),
                ipAddress,
                userAgent
            );
            auditLogRepository.save(auditLog);
            
            // Update metrics
            loginFailures.increment();
            
            return AuthenticationResult.failure(message);
            
        } catch (Exception e) {
            logger.error("Error handling authentication failure", e);
            return AuthenticationResult.failure("Authentication failed");
        }
    }

    /**
     * Checks if a user account is currently locked.
     * 
     * @param email the user's email address
     * @return true if the account is locked
     */
    @Transactional(readOnly = true)
    public boolean isAccountLocked(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        return userOptional.map(User::isAccountLocked).orElse(false);
    }

    /**
     * Gets the remaining time until account unlock.
     * 
     * @param email the user's email address
     * @return minutes until unlock, or 0 if not locked
     */
    @Transactional(readOnly = true)
    public long getMinutesUntilUnlock(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            return 0;
        }
        
        User user = userOptional.get();
        if (!user.isAccountLocked()) {
            return 0;
        }
        
        LocalDateTime now = LocalDateTime.now();
        return java.time.Duration.between(now, user.getLockedUntil()).toMinutes();
    }

    /**
     * Manually unlocks a user account (for administrative purposes).
     * 
     * @param email the user's email address
     * @param adminIpAddress the administrator's IP address
     * @param adminUserAgent the administrator's user agent
     * @return true if the account was unlocked
     */
    public boolean unlockAccount(String email, String adminIpAddress, String adminUserAgent) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isEmpty()) {
            return false;
        }
        
        User user = userOptional.get();
        if (!user.isAccountLocked()) {
            return false; // Account is not locked
        }
        
        try {
            userRepository.unlockUserAccount(user.getId());
            
            // Log account unlock
            AuditLog unlockLog = AuditLog.success(
                user.getId(),
                AuditLog.EVENT_ACCOUNT_UNLOCKED,
                "Account manually unlocked by administrator",
                adminIpAddress,
                adminUserAgent
            );
            auditLogRepository.save(unlockLog);
            
            logger.info("Account manually unlocked for user ID: {}, Email: {}", user.getId(), email);
            return true;
            
        } catch (Exception e) {
            logger.error("Error unlocking account for user ID: {}", user.getId(), e);
            return false;
        }
    }

    /**
     * Result class for authentication operations.
     */
    public static class AuthenticationResult {
        private final boolean success;
        private final String message;
        private final User user;
        private final String accessToken;
        private final String refreshToken;

        private AuthenticationResult(boolean success, String message, User user, 
                                   String accessToken, String refreshToken) {
            this.success = success;
            this.message = message;
            this.user = user;
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }

        public static AuthenticationResult success(User user, String accessToken, String refreshToken) {
            return new AuthenticationResult(true, "Authentication successful", user, accessToken, refreshToken);
        }

        public static AuthenticationResult failure(String message) {
            return new AuthenticationResult(false, message, null, null, null);
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public User getUser() { return user; }
        public String getAccessToken() { return accessToken; }
        public String getRefreshToken() { return refreshToken; }
    }
}