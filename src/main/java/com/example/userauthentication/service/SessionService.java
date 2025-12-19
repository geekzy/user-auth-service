package com.example.userauthentication.service;

import com.example.userauthentication.model.AuditLog;
import com.example.userauthentication.model.Session;
import com.example.userauthentication.repository.AuditLogRepository;
import com.example.userauthentication.repository.SessionRepository;
import com.example.userauthentication.security.JwtTokenService;
import io.micrometer.core.annotation.Timed;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Service class for session management operations.
 * Handles session lifecycle, logout functionality with JWT blacklisting,
 * audit logging, and performance metrics integration.
 * 
 * Requirements: 3.1, 3.3, 3.4
 */
@Service
@Transactional
public class SessionService {

    private static final Logger logger = LoggerFactory.getLogger(SessionService.class);

    private final SessionRepository sessionRepository;
    private final AuditLogRepository auditLogRepository;
    private final JwtTokenService jwtTokenService;
    private final SessionCleanupService sessionCleanupService;
    
    // Metrics
    private final Counter logoutAttempts;
    private final Counter logoutSuccesses;
    private final Counter logoutFailures;
    private final Counter sessionInvalidations;
    private final Counter sessionExtensions;
    private final Timer logoutTimer;
    private final Timer sessionValidationTimer;

    public SessionService(SessionRepository sessionRepository,
                         AuditLogRepository auditLogRepository,
                         JwtTokenService jwtTokenService,
                         SessionCleanupService sessionCleanupService,
                         MeterRegistry meterRegistry) {
        this.sessionRepository = sessionRepository;
        this.auditLogRepository = auditLogRepository;
        this.jwtTokenService = jwtTokenService;
        this.sessionCleanupService = sessionCleanupService;
        
        // Initialize metrics
        this.logoutAttempts = Counter.builder("auth.logout.attempts")
                .description("Total number of logout attempts")
                .register(meterRegistry);
        this.logoutSuccesses = Counter.builder("auth.logout.successes")
                .description("Total number of successful logouts")
                .register(meterRegistry);
        this.logoutFailures = Counter.builder("auth.logout.failures")
                .description("Total number of failed logouts")
                .register(meterRegistry);
        this.sessionInvalidations = Counter.builder("auth.session.invalidations")
                .description("Total number of session invalidations")
                .register(meterRegistry);
        this.sessionExtensions = Counter.builder("auth.session.extensions")
                .description("Total number of session extensions")
                .register(meterRegistry);
        this.logoutTimer = Timer.builder("auth.logout.duration")
                .description("Time taken to process logout requests")
                .register(meterRegistry);
        this.sessionValidationTimer = Timer.builder("auth.session.validation.duration")
                .description("Time taken to validate sessions")
                .register(meterRegistry);
    }

    /**
     * Logs out a user by invalidating their session and blacklisting JWT tokens.
     * Implements comprehensive logout with audit logging and performance metrics.
     * 
     * @param sessionId the session ID to invalidate (optional)
     * @param accessToken the JWT access token to blacklist
     * @param refreshToken the JWT refresh token to blacklist (optional)
     * @param ipAddress the client's IP address for audit logging
     * @param userAgent the client's user agent for audit logging
     * @return LogoutResult containing success status and details
     */
    @Timed(value = "auth.logout.processing.time", description = "Time taken to process logout request")
    public LogoutResult logout(String sessionId, String accessToken, String refreshToken, 
                              String ipAddress, String userAgent) {
        logoutAttempts.increment();
        
        Timer.Sample sample = Timer.start();
        try {
            logger.info("Logout attempt for session: {} from IP: {}", sessionId, ipAddress);
            
            // Extract user ID from access token for audit logging
            Long userId = null;
            if (accessToken != null) {
                userId = jwtTokenService.extractUserIdFromToken(accessToken);
            }
            
            // Validate input
            if (accessToken == null || accessToken.trim().isEmpty()) {
                return handleLogoutFailure(userId, "Access token is required for logout", 
                                         ipAddress, userAgent, "MISSING_TOKEN");
            }
            
            // Blacklist JWT tokens
            jwtTokenService.blacklistToken(accessToken);
            if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                jwtTokenService.blacklistToken(refreshToken);
            }
            
            // Invalidate session if provided
            if (sessionId != null && !sessionId.trim().isEmpty()) {
                invalidateSessionById(sessionId);
            }
            
            // If we have a user ID, invalidate all their sessions for security
            if (userId != null) {
                invalidateAllUserSessions(userId);
            }
            
            // Log successful logout
            AuditLog auditLog = AuditLog.success(
                userId,
                AuditLog.EVENT_USER_LOGOUT,
                "User successfully logged out",
                ipAddress,
                userAgent
            );
            auditLogRepository.save(auditLog);
            
            // Trigger async session cleanup
            triggerAsyncSessionCleanup();
            
            // Update metrics
            logoutSuccesses.increment();
            
            logger.info("Successful logout for user ID: {} from IP: {}", userId, ipAddress);
            
            return LogoutResult.success("Logout successful");
            
        } catch (Exception e) {
            logger.error("Unexpected error during logout for session: {}", sessionId, e);
            return handleLogoutFailure(null, "Logout failed due to an internal error", 
                                     ipAddress, userAgent, "INTERNAL_ERROR");
        } finally {
            sample.stop(logoutTimer);
        }
    }

    /**
     * Validates a session and optionally extends its expiration.
     * 
     * @param sessionId the session ID to validate
     * @param extendSession whether to extend the session if valid
     * @return SessionValidationResult containing validation status and session info
     */
    @Timed(value = "auth.session.validation.processing.time", description = "Time taken to validate session")
    public SessionValidationResult validateSession(String sessionId, boolean extendSession) {
        Timer.Sample sample = Timer.start();
        try {
            if (sessionId == null || sessionId.trim().isEmpty()) {
                return SessionValidationResult.invalid("Session ID is required");
            }
            
            Optional<Session> sessionOptional = sessionRepository.findActiveSessionById(sessionId);
            if (sessionOptional.isEmpty()) {
                logger.debug("Session not found or inactive: {}", sessionId);
                return SessionValidationResult.invalid("Session not found or expired");
            }
            
            Session session = sessionOptional.get();
            
            // Check if session is expired
            if (session.isExpired()) {
                logger.debug("Session expired: {}", sessionId);
                invalidateSessionById(sessionId);
                return SessionValidationResult.invalid("Session has expired");
            }
            
            // Extend session if requested
            if (extendSession) {
                extendSessionExpiration(sessionId, 30); // Extend by 30 minutes
                sessionExtensions.increment();
            } else {
                // Just update last accessed time
                session.updateLastAccessed();
                sessionRepository.updateLastAccessedTime(sessionId, LocalDateTime.now());
            }
            
            return SessionValidationResult.valid(session);
            
        } catch (Exception e) {
            logger.error("Error validating session: {}", sessionId, e);
            return SessionValidationResult.invalid("Session validation failed");
        } finally {
            sample.stop(sessionValidationTimer);
        }
    }

    /**
     * Invalidates a specific session by ID.
     * 
     * @param sessionId the session ID to invalidate
     * @return true if the session was successfully invalidated
     */
    public boolean invalidateSessionById(String sessionId) {
        try {
            if (sessionId == null || sessionId.trim().isEmpty()) {
                return false;
            }
            
            sessionRepository.invalidateSession(sessionId);
            sessionInvalidations.increment();
            
            logger.debug("Session invalidated: {}", sessionId);
            return true;
            
        } catch (Exception e) {
            logger.error("Error invalidating session: {}", sessionId, e);
            return false;
        }
    }

    /**
     * Invalidates all active sessions for a specific user.
     * 
     * @param userId the user ID whose sessions should be invalidated
     * @return number of sessions that were invalidated
     */
    public int invalidateAllUserSessions(Long userId) {
        try {
            if (userId == null) {
                return 0;
            }
            
            List<Session> activeSessions = sessionRepository.findActiveSessionsByUserId(userId);
            int sessionCount = activeSessions.size();
            
            if (sessionCount > 0) {
                sessionRepository.invalidateAllUserSessions(userId);
                sessionInvalidations.increment(sessionCount);
                
                logger.info("Invalidated {} active sessions for user ID: {}", sessionCount, userId);
            }
            
            return sessionCount;
            
        } catch (Exception e) {
            logger.error("Error invalidating all sessions for user ID: {}", userId, e);
            return 0;
        }
    }

    /**
     * Extends the expiration time of a session.
     * 
     * @param sessionId the session ID to extend
     * @param extensionMinutes number of minutes to extend the session
     * @return true if the session was successfully extended
     */
    public boolean extendSessionExpiration(String sessionId, int extensionMinutes) {
        try {
            if (sessionId == null || sessionId.trim().isEmpty() || extensionMinutes <= 0) {
                return false;
            }
            
            LocalDateTime newExpirationTime = LocalDateTime.now().plusMinutes(extensionMinutes);
            sessionRepository.extendSessionExpiration(sessionId, newExpirationTime);
            
            logger.debug("Session extended: {} for {} minutes", sessionId, extensionMinutes);
            return true;
            
        } catch (Exception e) {
            logger.error("Error extending session: {}", sessionId, e);
            return false;
        }
    }

    /**
     * Gets all active sessions for a user.
     * 
     * @param userId the user ID to get sessions for
     * @return list of active sessions for the user
     */
    @Transactional(readOnly = true)
    public List<Session> getActiveUserSessions(Long userId) {
        try {
            if (userId == null) {
                return List.of();
            }
            
            return sessionRepository.findActiveSessionsByUserId(userId);
            
        } catch (Exception e) {
            logger.error("Error retrieving active sessions for user ID: {}", userId, e);
            return List.of();
        }
    }

    /**
     * Checks if a user has any active sessions.
     * 
     * @param userId the user ID to check
     * @return true if the user has at least one active session
     */
    @Transactional(readOnly = true)
    public boolean hasActiveSession(Long userId) {
        try {
            if (userId == null) {
                return false;
            }
            
            return sessionRepository.hasActiveSession(userId);
            
        } catch (Exception e) {
            logger.error("Error checking active sessions for user ID: {}", userId, e);
            return false;
        }
    }

    /**
     * Triggers asynchronous session cleanup.
     * This method runs in the background to clean up expired sessions.
     */
    @Async
    public CompletableFuture<Void> triggerAsyncSessionCleanup() {
        try {
            logger.debug("Triggering async session cleanup");
            sessionCleanupService.cleanupExpiredSessions();
            return CompletableFuture.completedFuture(null);
        } catch (Exception e) {
            logger.error("Error during async session cleanup", e);
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Handles logout failures by logging the event and updating metrics.
     */
    private LogoutResult handleLogoutFailure(Long userId, String message, 
                                           String ipAddress, String userAgent, String reason) {
        try {
            // Log failed logout
            AuditLog auditLog = AuditLog.failure(
                userId,
                AuditLog.EVENT_USER_LOGOUT,
                String.format("Logout failed: %s", reason),
                ipAddress,
                userAgent
            );
            auditLogRepository.save(auditLog);
            
            // Update metrics
            logoutFailures.increment();
            
            return LogoutResult.failure(message);
            
        } catch (Exception e) {
            logger.error("Error handling logout failure", e);
            return LogoutResult.failure("Logout failed");
        }
    }

    /**
     * Result class for logout operations.
     */
    public static class LogoutResult {
        private final boolean success;
        private final String message;

        private LogoutResult(boolean success, String message) {
            this.success = success;
            this.message = message;
        }

        public static LogoutResult success(String message) {
            return new LogoutResult(true, message);
        }

        public static LogoutResult failure(String message) {
            return new LogoutResult(false, message);
        }

        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }

        @Override
        public String toString() {
            return String.format("LogoutResult{success=%s, message='%s'}", success, message);
        }
    }

    /**
     * Result class for session validation operations.
     */
    public static class SessionValidationResult {
        private final boolean valid;
        private final String message;
        private final Session session;

        private SessionValidationResult(boolean valid, String message, Session session) {
            this.valid = valid;
            this.message = message;
            this.session = session;
        }

        public static SessionValidationResult valid(Session session) {
            return new SessionValidationResult(true, "Session is valid", session);
        }

        public static SessionValidationResult invalid(String message) {
            return new SessionValidationResult(false, message, null);
        }

        public boolean isValid() { return valid; }
        public String getMessage() { return message; }
        public Session getSession() { return session; }

        @Override
        public String toString() {
            return String.format("SessionValidationResult{valid=%s, message='%s'}", valid, message);
        }
    }
}