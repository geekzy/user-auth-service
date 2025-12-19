package com.example.userauthentication.service;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;

/**
 * Service for recording authentication-related metrics.
 * Provides a centralized way to track authentication operations.
 */
@Service
public class MetricsService {

    private final Counter userRegistrationSuccessCounter;
    private final Counter userRegistrationFailureCounter;
    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;
    private final Counter logoutCounter;
    private final Counter passwordResetRequestCounter;
    private final Counter passwordResetSuccessCounter;
    private final Timer authenticationTimer;
    private final Timer passwordHashingTimer;
    private final Counter rateLimitViolationCounter;
    private final Counter jwtTokenGenerationCounter;
    private final Counter jwtTokenValidationCounter;
    private final Counter sessionCreationCounter;
    private final Counter sessionInvalidationCounter;
    private final Timer databaseOperationTimer;
    private final Counter authenticationSuccessRateCounter;
    private final Counter authenticationFailureRateCounter;

    public MetricsService(Counter userRegistrationSuccessCounter,
                         Counter userRegistrationFailureCounter,
                         Counter loginSuccessCounter,
                         Counter loginFailureCounter,
                         Counter logoutCounter,
                         Counter passwordResetRequestCounter,
                         Counter passwordResetSuccessCounter,
                         Timer authenticationTimer,
                         Timer passwordHashingTimer,
                         Counter rateLimitViolationCounter,
                         Counter jwtTokenGenerationCounter,
                         Counter jwtTokenValidationCounter,
                         Counter sessionCreationCounter,
                         Counter sessionInvalidationCounter,
                         Timer databaseOperationTimer,
                         Counter authenticationSuccessRateCounter,
                         Counter authenticationFailureRateCounter) {
        this.userRegistrationSuccessCounter = userRegistrationSuccessCounter;
        this.userRegistrationFailureCounter = userRegistrationFailureCounter;
        this.loginSuccessCounter = loginSuccessCounter;
        this.loginFailureCounter = loginFailureCounter;
        this.logoutCounter = logoutCounter;
        this.passwordResetRequestCounter = passwordResetRequestCounter;
        this.passwordResetSuccessCounter = passwordResetSuccessCounter;
        this.authenticationTimer = authenticationTimer;
        this.passwordHashingTimer = passwordHashingTimer;
        this.rateLimitViolationCounter = rateLimitViolationCounter;
        this.jwtTokenGenerationCounter = jwtTokenGenerationCounter;
        this.jwtTokenValidationCounter = jwtTokenValidationCounter;
        this.sessionCreationCounter = sessionCreationCounter;
        this.sessionInvalidationCounter = sessionInvalidationCounter;
        this.databaseOperationTimer = databaseOperationTimer;
        this.authenticationSuccessRateCounter = authenticationSuccessRateCounter;
        this.authenticationFailureRateCounter = authenticationFailureRateCounter;
    }

    /**
     * Record a successful user registration.
     */
    public void recordUserRegistrationSuccess() {
        userRegistrationSuccessCounter.increment();
    }

    /**
     * Record a failed user registration.
     */
    public void recordUserRegistrationFailure() {
        userRegistrationFailureCounter.increment();
    }

    /**
     * Record a successful login attempt.
     */
    public void recordLoginSuccess() {
        loginSuccessCounter.increment();
    }

    /**
     * Record a failed login attempt.
     */
    public void recordLoginFailure() {
        loginFailureCounter.increment();
    }

    /**
     * Record a logout operation.
     */
    public void recordLogout() {
        logoutCounter.increment();
    }

    /**
     * Record a password reset request.
     */
    public void recordPasswordResetRequest() {
        passwordResetRequestCounter.increment();
    }

    /**
     * Record a successful password reset.
     */
    public void recordPasswordResetSuccess() {
        passwordResetSuccessCounter.increment();
    }

    /**
     * Record a rate limit violation.
     */
    public void recordRateLimitViolation() {
        rateLimitViolationCounter.increment();
    }

    /**
     * Record JWT token generation.
     */
    public void recordJwtTokenGeneration() {
        jwtTokenGenerationCounter.increment();
    }

    /**
     * Record JWT token validation attempt.
     */
    public void recordJwtTokenValidation() {
        jwtTokenValidationCounter.increment();
    }

    /**
     * Record session creation.
     */
    public void recordSessionCreation() {
        sessionCreationCounter.increment();
    }

    /**
     * Record session invalidation.
     */
    public void recordSessionInvalidation() {
        sessionInvalidationCounter.increment();
    }

    /**
     * Get the authentication timer for measuring operation duration.
     */
    public Timer getAuthenticationTimer() {
        return authenticationTimer;
    }

    /**
     * Get the password hashing timer for measuring hashing duration.
     */
    public Timer getPasswordHashingTimer() {
        return passwordHashingTimer;
    }

    /**
     * Get the database operation timer for measuring database operation duration.
     */
    public Timer getDatabaseOperationTimer() {
        return databaseOperationTimer;
    }

    /**
     * Record authentication success for rate calculation.
     */
    public void recordAuthenticationSuccess() {
        authenticationSuccessRateCounter.increment();
    }

    /**
     * Record authentication failure for rate calculation.
     */
    public void recordAuthenticationFailure() {
        authenticationFailureRateCounter.increment();
    }
}