package com.example.userauthentication.service;

import com.example.userauthentication.model.PasswordResetToken;
import com.example.userauthentication.model.User;
import com.example.userauthentication.repository.PasswordResetTokenRepository;
import com.example.userauthentication.repository.UserRepository;
import com.example.userauthentication.security.RateLimited;
import io.micrometer.core.annotation.Timed;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Service for handling password reset operations.
 * Implements secure token generation and silent handling for unregistered emails.
 * 
 * Requirements: 4.1, 4.2, 4.4, 4.5
 */
@Service
@Transactional
public class PasswordResetService {

    private static final Logger logger = LoggerFactory.getLogger(PasswordResetService.class);
    
    @Value("${app.security.password-reset.token-expiration-minutes:60}")
    private int tokenExpirationMinutes;
    
    @Value("${app.security.password-reset.silent-delay-ms:500}")
    private long silentDelayMs;

    private final PasswordResetTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final Counter resetRequestCounter;
    private final Counter resetSuccessCounter;
    private final Counter resetFailureCounter;

    public PasswordResetService(
            PasswordResetTokenRepository tokenRepository,
            UserRepository userRepository,
            EmailService emailService,
            PasswordEncoder passwordEncoder,
            MeterRegistry meterRegistry) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.passwordEncoder = passwordEncoder;
        
        // Initialize metrics
        this.resetRequestCounter = Counter.builder("password.reset.requests")
                .description("Total number of password reset requests")
                .register(meterRegistry);
        this.resetSuccessCounter = Counter.builder("password.reset.successes")
                .description("Total number of successful password resets")
                .register(meterRegistry);
        this.resetFailureCounter = Counter.builder("password.reset.failures")
                .description("Total number of failed password resets")
                .register(meterRegistry);
    }

    /**
     * Initiates a password reset request for the given email address.
     * Implements silent handling for unregistered emails with consistent timing
     * to prevent email enumeration attacks.
     * 
     * Requirements: 4.1, 4.2
     * 
     * @param email the email address requesting password reset
     */
    @RateLimited(maxAttempts = 3, windowMinutes = 60, keyPrefix = "password_reset")
    @Timed(value = "password.reset.request.duration", description = "Time taken to process password reset request")
    public void requestPasswordReset(String email) {
        resetRequestCounter.increment();
        
        long startTime = System.currentTimeMillis();
        
        try {
            logger.info("Password reset requested for email: {}", email);
            
            // Validate email format
            if (email == null || email.trim().isEmpty() || !isValidEmailFormat(email)) {
                logger.warn("Invalid email format for password reset: {}", email);
                // Still apply consistent timing
                applyConsistentTiming(startTime);
                return;
            }
            
            // Find user by email
            Optional<User> userOptional = userRepository.findByEmail(email);
            
            if (userOptional.isPresent()) {
                User user = userOptional.get();
                
                // Invalidate any existing tokens for this user
                tokenRepository.invalidateExistingTokensForUser(user.getId(), LocalDateTime.now());
                
                // Generate new reset token
                PasswordResetToken resetToken = new PasswordResetToken(user.getId(), tokenExpirationMinutes);
                tokenRepository.save(resetToken);
                
                // Send reset email
                emailService.sendPasswordResetEmail(user.getEmail(), resetToken.getToken());
                
                logger.info("Password reset token generated and email sent for user ID: {}", user.getId());
            } else {
                // User not found - handle silently
                logger.info("Password reset requested for unregistered email: {} - handling silently", email);
                
                // No email sent, no token generated, but we maintain consistent timing
                // This prevents attackers from determining if an email is registered
            }
            
            // Apply consistent timing to prevent timing attacks
            applyConsistentTiming(startTime);
            
        } catch (Exception e) {
            resetFailureCounter.increment();
            logger.error("Error processing password reset request for email: {}", email, e);
            
            // Still apply consistent timing even on error
            applyConsistentTiming(startTime);
            
            // Don't throw exception to maintain consistent behavior
        }
    }

    /**
     * Completes the password reset process by validating the token and updating the password.
     * 
     * Requirements: 4.4, 4.5
     * 
     * @param token the password reset token
     * @param newPassword the new password
     * @return true if password was successfully reset
     * @throws IllegalArgumentException if token is invalid or password is weak
     */
    @Timed(value = "password.reset.completion.duration", description = "Time taken to complete password reset")
    public boolean completePasswordReset(String token, String newPassword) {
        try {
            logger.info("Attempting to complete password reset with token: {}", 
                       token != null ? token.substring(0, Math.min(8, token.length())) + "..." : "null");
            
            // Validate inputs
            if (token == null || token.trim().isEmpty()) {
                logger.warn("Password reset attempted with null or empty token");
                resetFailureCounter.increment();
                throw new IllegalArgumentException("Reset token is required");
            }
            
            if (newPassword == null || newPassword.isEmpty()) {
                logger.warn("Password reset attempted with null or empty password");
                resetFailureCounter.increment();
                throw new IllegalArgumentException("New password is required");
            }
            
            // Validate password strength
            if (!User.isPasswordStrong(newPassword)) {
                logger.warn("Password reset attempted with weak password");
                resetFailureCounter.increment();
                throw new IllegalArgumentException(
                    "Password must be at least 8 characters long and contain at least one uppercase letter, " +
                    "one lowercase letter, one digit, and one special character"
                );
            }
            
            // Find and validate token
            Optional<PasswordResetToken> tokenOptional = tokenRepository.findByToken(token);
            
            if (tokenOptional.isEmpty()) {
                logger.warn("Password reset attempted with non-existent token");
                resetFailureCounter.increment();
                throw new IllegalArgumentException("Invalid or expired reset token");
            }
            
            PasswordResetToken resetToken = tokenOptional.get();
            
            // Check if token is valid (not used and not expired)
            if (!resetToken.isValid()) {
                logger.warn("Password reset attempted with invalid token - used: {}, expired: {}", 
                           resetToken.isUsed(), resetToken.isExpired());
                resetFailureCounter.increment();
                throw new IllegalArgumentException("Invalid or expired reset token");
            }
            
            // Get user
            Optional<User> userOptional = userRepository.findById(resetToken.getUserId());
            
            if (userOptional.isEmpty()) {
                logger.error("Password reset token references non-existent user ID: {}", resetToken.getUserId());
                resetFailureCounter.increment();
                throw new IllegalArgumentException("Invalid reset token");
            }
            
            User user = userOptional.get();
            
            // Update password
            String hashedPassword = passwordEncoder.encode(newPassword);
            user.setPasswordHash(hashedPassword);
            userRepository.save(user);
            
            // Mark token as used
            resetToken.markAsUsed();
            tokenRepository.save(resetToken);
            
            resetSuccessCounter.increment();
            logger.info("Password successfully reset for user ID: {}", user.getId());
            
            return true;
            
        } catch (IllegalArgumentException e) {
            // These are expected validation errors, re-throw them
            throw e;
        } catch (Exception e) {
            resetFailureCounter.increment();
            logger.error("Unexpected error during password reset completion", e);
            throw new RuntimeException("Password reset failed due to an internal error", e);
        }
    }

    /**
     * Validates a reset token without using it.
     * 
     * @param token the token to validate
     * @return true if token is valid
     */
    @Transactional(readOnly = true)
    public boolean isTokenValid(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        Optional<PasswordResetToken> tokenOptional = tokenRepository.findByToken(token);
        return tokenOptional.isPresent() && tokenOptional.get().isValid();
    }

    /**
     * Cleans up expired and used tokens.
     * Should be called periodically by a scheduled task.
     */
    @Transactional
    public void cleanupExpiredTokens() {
        LocalDateTime now = LocalDateTime.now();
        
        // Delete expired tokens
        int expiredCount = tokenRepository.deleteExpiredTokens(now);
        
        // Delete used tokens older than 7 days
        LocalDateTime cutoffDate = now.minusDays(7);
        int usedCount = tokenRepository.deleteUsedTokensOlderThan(cutoffDate);
        
        logger.info("Cleaned up {} expired tokens and {} old used tokens", expiredCount, usedCount);
    }

    /**
     * Applies consistent timing to prevent timing attacks.
     * Ensures the operation takes at least the configured delay time.
     * 
     * @param startTime the start time of the operation in milliseconds
     */
    private void applyConsistentTiming(long startTime) {
        long elapsed = System.currentTimeMillis() - startTime;
        long remainingDelay = silentDelayMs - elapsed;
        
        if (remainingDelay > 0) {
            try {
                Thread.sleep(remainingDelay);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("Interrupted while applying consistent timing delay", e);
            }
        }
    }

    /**
     * Basic email format validation.
     * 
     * @param email the email to validate
     * @return true if email format is valid
     */
    private boolean isValidEmailFormat(String email) {
        if (email == null || email.trim().isEmpty()) {
            return false;
        }
        
        // Basic email validation - contains @ and has characters before and after
        String trimmed = email.trim();
        int atIndex = trimmed.indexOf('@');
        
        return atIndex > 0 && atIndex < trimmed.length() - 1 && trimmed.indexOf('@', atIndex + 1) == -1;
    }
}
