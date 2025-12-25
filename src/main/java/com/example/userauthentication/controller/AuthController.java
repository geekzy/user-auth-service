package com.example.userauthentication.controller;

import com.example.userauthentication.dto.*;
import com.example.userauthentication.exception.InvalidPasswordException;
import com.example.userauthentication.exception.UserAlreadyExistsException;
import com.example.userauthentication.model.Session;
import com.example.userauthentication.security.JwtTokenService;
import com.example.userauthentication.security.RateLimited;
import com.example.userauthentication.service.AuthenticationService;
import com.example.userauthentication.service.PasswordResetService;
import com.example.userauthentication.service.SessionService;
import com.example.userauthentication.service.UserService;
import io.micrometer.core.annotation.Timed;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

/**
 * REST controller for authentication operations.
 * Provides endpoints for user registration, login, logout, password reset, and session management.
 * 
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.3, 3.4, 4.1, 4.2, 4.4, 4.5, 6.1, 6.2
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*", maxAge = 3600)
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final AuthenticationService authenticationService;
    private final SessionService sessionService;
    private final PasswordResetService passwordResetService;
    private final JwtTokenService jwtTokenService;
    
    // Metrics
    private final Counter registrationRequests;
    private final Counter loginRequests;
    private final Counter logoutRequests;
    private final Counter passwordResetRequests;
    private final Counter sessionValidationRequests;

    public AuthController(UserService userService,
                         AuthenticationService authenticationService,
                         SessionService sessionService,
                         PasswordResetService passwordResetService,
                         JwtTokenService jwtTokenService,
                         MeterRegistry meterRegistry) {
        this.userService = userService;
        this.authenticationService = authenticationService;
        this.sessionService = sessionService;
        this.passwordResetService = passwordResetService;
        this.jwtTokenService = jwtTokenService;
        
        // Initialize metrics
        this.registrationRequests = Counter.builder("api.auth.registration.requests")
                .description("Total number of registration API requests")
                .register(meterRegistry);
        this.loginRequests = Counter.builder("api.auth.login.requests")
                .description("Total number of login API requests")
                .register(meterRegistry);
        this.logoutRequests = Counter.builder("api.auth.logout.requests")
                .description("Total number of logout API requests")
                .register(meterRegistry);
        this.passwordResetRequests = Counter.builder("api.auth.password.reset.requests")
                .description("Total number of password reset API requests")
                .register(meterRegistry);
        this.sessionValidationRequests = Counter.builder("api.auth.session.validation.requests")
                .description("Total number of session validation API requests")
                .register(meterRegistry);
    }

    /**
     * Registers a new user account.
     * 
     * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
     * 
     * @param request the user registration request
     * @param bindingResult validation results
     * @param httpRequest HTTP request for IP address extraction
     * @return ResponseEntity with registration response or error details
     */
    @PostMapping("/register")
    @Timed(value = "api.auth.register.duration", description = "Time taken to process registration requests")
    public ResponseEntity<?> register(@Valid @RequestBody UserRegistrationRequest request,
                                     BindingResult bindingResult,
                                     HttpServletRequest httpRequest) {
        registrationRequests.increment();
        
        try {
            logger.info("Registration request received for email: {} from IP: {}", 
                       request.getEmail(), getClientIpAddress(httpRequest));
            
            // Check for validation errors
            if (bindingResult.hasErrors()) {
                String errorMessage = bindingResult.getFieldErrors().stream()
                        .map(error -> error.getField() + ": " + error.getDefaultMessage())
                        .collect(Collectors.joining(", "));
                
                logger.warn("Registration validation failed: {}", errorMessage);
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure("Validation failed: " + errorMessage));
            }
            
            // Additional password confirmation check
            if (!request.isPasswordConfirmed()) {
                logger.warn("Registration failed: password confirmation mismatch for email: {}", request.getEmail());
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure("Password and confirmation password do not match"));
            }
            
            // Register user
            UserRegistrationResponse response = userService.registerUser(request);
            
            logger.info("Registration successful for email: {} with user ID: {}", 
                       response.getEmail(), response.getId());
            
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
            
        } catch (UserAlreadyExistsException e) {
            logger.warn("Registration failed - user already exists: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(ApiResponse.failure(e.getMessage()));
        } catch (InvalidPasswordException e) {
            logger.warn("Registration failed - invalid password: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.failure(e.getMessage()));
        } catch (IllegalArgumentException e) {
            logger.warn("Registration failed - invalid input: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.failure(e.getMessage()));
        } catch (Exception e) {
            logger.error("Unexpected error during registration for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("Registration failed due to an internal error"));
        }
    }

    /**
     * Authenticates a user and creates a session.
     * 
     * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
     * 
     * @param request the login request
     * @param bindingResult validation results
     * @param httpRequest HTTP request for IP address and user agent extraction
     * @return ResponseEntity with login response including JWT tokens or error details
     */
    @PostMapping("/login")
    @RateLimited(maxAttempts = 10, windowMinutes = 15, keyPrefix = "login", useIpAddress = true)
    @Timed(value = "api.auth.login.duration", description = "Time taken to process login requests")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request,
                                  BindingResult bindingResult,
                                  HttpServletRequest httpRequest) {
        loginRequests.increment();
        
        try {
            String ipAddress = getClientIpAddress(httpRequest);
            String userAgent = getUserAgent(httpRequest);
            
            logger.info("Login request received for email: {} from IP: {}", request.getEmail(), ipAddress);
            
            // Check for validation errors
            if (bindingResult.hasErrors()) {
                String errorMessage = bindingResult.getFieldErrors().stream()
                        .map(error -> error.getField() + ": " + error.getDefaultMessage())
                        .collect(Collectors.joining(", "));
                
                logger.warn("Login validation failed: {}", errorMessage);
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure("Validation failed: " + errorMessage));
            }
            
            // Authenticate user
            AuthenticationService.AuthenticationResult authResult = 
                    authenticationService.authenticate(request.getEmail(), request.getPassword(), ipAddress, userAgent);
            
            if (!authResult.isSuccess()) {
                logger.warn("Login failed for email: {} - {}", request.getEmail(), authResult.getMessage());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(ApiResponse.failure(authResult.getMessage()));
            }
            
            // Create login response
            LoginResponse response = LoginResponse.success(
                    authResult.getUser().getId(),
                    authResult.getUser().getEmail(),
                    authResult.getAccessToken(),
                    authResult.getRefreshToken(),
                    LocalDateTime.now()
            );
            
            logger.info("Login successful for user ID: {} from IP: {}", 
                       authResult.getUser().getId(), ipAddress);
            
            return ResponseEntity.ok()
                    .header("Authorization", "Bearer " + authResult.getAccessToken())
                    .body(response);
            
        } catch (Exception e) {
            logger.error("Unexpected error during login for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("Login failed due to an internal error"));
        }
    }

    /**
     * Logs out a user by invalidating their session and blacklisting JWT tokens.
     * 
     * Requirements: 3.1, 3.3, 3.4
     * 
     * @param httpRequest HTTP request for token and client information extraction
     * @return ResponseEntity with logout confirmation or error details
     */
    @PostMapping("/logout")
    @Timed(value = "api.auth.logout.duration", description = "Time taken to process logout requests")
    public ResponseEntity<?> logout(HttpServletRequest httpRequest) {
        logoutRequests.increment();
        
        try {
            String ipAddress = getClientIpAddress(httpRequest);
            String userAgent = getUserAgent(httpRequest);
            String accessToken = extractTokenFromRequest(httpRequest);
            String refreshToken = httpRequest.getHeader("X-Refresh-Token");
            String sessionId = httpRequest.getHeader("X-Session-Id");
            
            logger.info("Logout request received from IP: {}", ipAddress);
            
            // Perform logout
            SessionService.LogoutResult logoutResult = sessionService.logout(
                    sessionId, accessToken, refreshToken, ipAddress, userAgent);
            
            if (!logoutResult.isSuccess()) {
                logger.warn("Logout failed from IP: {} - {}", ipAddress, logoutResult.getMessage());
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure(logoutResult.getMessage()));
            }
            
            logger.info("Logout successful from IP: {}", ipAddress);
            
            return ResponseEntity.ok()
                    .body(ApiResponse.success(logoutResult.getMessage()));
            
        } catch (Exception e) {
            logger.error("Unexpected error during logout", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("Logout failed due to an internal error"));
        }
    }

    /**
     * Initiates a password reset request.
     * 
     * Requirements: 4.1, 4.2
     * 
     * @param request the password reset request
     * @param bindingResult validation results
     * @param httpRequest HTTP request for IP address extraction
     * @return ResponseEntity with confirmation message
     */
    @PostMapping("/reset-request")
    @RateLimited(maxAttempts = 3, windowMinutes = 60, keyPrefix = "password_reset", useIpAddress = true)
    @Timed(value = "api.auth.password.reset.request.duration", description = "Time taken to process password reset requests")
    public ResponseEntity<?> requestPasswordReset(@Valid @RequestBody PasswordResetRequest request,
                                                 BindingResult bindingResult,
                                                 HttpServletRequest httpRequest) {
        passwordResetRequests.increment();
        
        try {
            logger.info("Password reset request received for email: {} from IP: {}", 
                       request.getEmail(), getClientIpAddress(httpRequest));
            
            // Check for validation errors
            if (bindingResult.hasErrors()) {
                String errorMessage = bindingResult.getFieldErrors().stream()
                        .map(error -> error.getField() + ": " + error.getDefaultMessage())
                        .collect(Collectors.joining(", "));
                
                logger.warn("Password reset validation failed: {}", errorMessage);
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure("Validation failed: " + errorMessage));
            }
            
            // Process password reset request
            passwordResetService.requestPasswordReset(request.getEmail());
            
            // Always return success message to prevent email enumeration
            return ResponseEntity.ok()
                    .body(ApiResponse.success("If the email address is registered, you will receive password reset instructions"));
            
        } catch (Exception e) {
            logger.error("Unexpected error during password reset request for email: {}", request.getEmail(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("Password reset request failed due to an internal error"));
        }
    }

    /**
     * Completes the password reset process.
     * 
     * Requirements: 4.4, 4.5
     * 
     * @param request the password reset confirmation request
     * @param bindingResult validation results
     * @param httpRequest HTTP request for IP address extraction
     * @return ResponseEntity with confirmation message or error details
     */
    @PostMapping("/reset-confirm")
    @Timed(value = "api.auth.password.reset.confirm.duration", description = "Time taken to process password reset confirmations")
    public ResponseEntity<?> confirmPasswordReset(@Valid @RequestBody PasswordResetConfirmRequest request,
                                                 BindingResult bindingResult,
                                                 HttpServletRequest httpRequest) {
        try {
            logger.info("Password reset confirmation request received from IP: {}", getClientIpAddress(httpRequest));
            
            // Check for validation errors
            if (bindingResult.hasErrors()) {
                String errorMessage = bindingResult.getFieldErrors().stream()
                        .map(error -> error.getField() + ": " + error.getDefaultMessage())
                        .collect(Collectors.joining(", "));
                
                logger.warn("Password reset confirmation validation failed: {}", errorMessage);
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure("Validation failed: " + errorMessage));
            }
            
            // Additional password confirmation check
            if (!request.isPasswordConfirmed()) {
                logger.warn("Password reset confirmation failed: password mismatch");
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure("New password and confirmation password do not match"));
            }
            
            // Complete password reset
            boolean success = passwordResetService.completePasswordReset(request.getToken(), request.getNewPassword());
            
            if (success) {
                logger.info("Password reset completed successfully");
                return ResponseEntity.ok()
                        .body(ApiResponse.success("Password has been reset successfully"));
            } else {
                logger.warn("Password reset completion failed");
                return ResponseEntity.badRequest()
                        .body(ApiResponse.failure("Password reset failed"));
            }
            
        } catch (IllegalArgumentException e) {
            logger.warn("Password reset confirmation failed - invalid input: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(ApiResponse.failure(e.getMessage()));
        } catch (Exception e) {
            logger.error("Unexpected error during password reset confirmation", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ApiResponse.failure("Password reset failed due to an internal error"));
        }
    }

    /**
     * Validates the current session and optionally extends it.
     * 
     * Requirements: 6.1, 6.2
     * 
     * @param extendSession whether to extend the session if valid (default: true)
     * @param httpRequest HTTP request for token extraction
     * @return ResponseEntity with session information or error details
     */
    @GetMapping("/session")
    @Cacheable(value = "sessionValidation", key = "#httpRequest.getHeader('Authorization')", unless = "#extendSession")
    @Timed(value = "api.auth.session.validation.duration", description = "Time taken to validate sessions")
    public ResponseEntity<?> validateSession(@RequestParam(defaultValue = "true") boolean extendSession,
                                           HttpServletRequest httpRequest) {
        sessionValidationRequests.increment();
        
        try {
            String accessToken = extractTokenFromRequest(httpRequest);
            
            if (accessToken == null) {
                logger.debug("Session validation failed: no access token provided");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(SessionResponse.invalid("Access token is required"));
            }
            
            // Validate JWT token
            if (!jwtTokenService.isTokenValid(accessToken)) {
                logger.debug("Session validation failed: invalid or expired token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(SessionResponse.invalid("Invalid or expired token"));
            }
            
            // Extract user information from token
            Long userId = jwtTokenService.extractUserIdFromToken(accessToken);
            String email = jwtTokenService.extractEmailFromToken(accessToken);
            
            if (userId == null || email == null) {
                logger.warn("Session validation failed: unable to extract user information from token");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(SessionResponse.invalid("Invalid token format"));
            }
            
            // Check if user has active sessions (optional additional validation)
            if (!sessionService.hasActiveSession(userId)) {
                logger.debug("Session validation failed: no active session found for user ID: {}", userId);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(SessionResponse.invalid("No active session found"));
            }
            
            // Create session response
            SessionResponse response = SessionResponse.valid(
                    userId,
                    email,
                    LocalDateTime.now(),
                    jwtTokenService.extractExpirationFromToken(accessToken)
            );
            
            logger.debug("Session validation successful for user ID: {}", userId);
            
            return ResponseEntity.ok().body(response);
            
        } catch (Exception e) {
            logger.error("Unexpected error during session validation", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(SessionResponse.invalid("Session validation failed due to an internal error"));
        }
    }

    /**
     * Extracts the client's IP address from the HTTP request.
     * Handles various proxy headers for accurate IP detection.
     * 
     * @param request the HTTP request
     * @return the client's IP address
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Extracts the user agent from the HTTP request.
     * 
     * @param request the HTTP request
     * @return the user agent string
     */
    private String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Unknown";
    }

    /**
     * Extracts the JWT token from the Authorization header.
     * 
     * @param request the HTTP request
     * @return the JWT token without the "Bearer " prefix, or null if not found
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }
}