package com.example.userauthentication.service;

import com.example.userauthentication.repository.SessionRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Service responsible for automatic session cleanup and maintenance.
 * Runs scheduled tasks to clean up expired and inactive sessions.
 * 
 * Requirements: 2.1, 3.1, 6.1, 6.2
 */
@Service
public class SessionCleanupService {

    private static final Logger logger = LoggerFactory.getLogger(SessionCleanupService.class);

    private final SessionRepository sessionRepository;
    private final Counter expiredSessionsCleanedCounter;
    private final Counter inactiveSessionsCleanedCounter;
    private final Counter oldSessionsDeletedCounter;

    @Value("${app.session.cleanup.inactive-threshold-hours:24}")
    private int inactiveThresholdHours;

    @Value("${app.session.cleanup.deletion-threshold-days:30}")
    private int deletionThresholdDays;

    @Value("${app.session.cleanup.enabled:true}")
    private boolean cleanupEnabled;

    @Autowired
    public SessionCleanupService(SessionRepository sessionRepository, MeterRegistry meterRegistry) {
        this.sessionRepository = sessionRepository;
        this.expiredSessionsCleanedCounter = Counter.builder("sessions.cleanup.expired")
            .description("Number of expired sessions cleaned up")
            .register(meterRegistry);
        this.inactiveSessionsCleanedCounter = Counter.builder("sessions.cleanup.inactive")
            .description("Number of inactive sessions cleaned up")
            .register(meterRegistry);
        this.oldSessionsDeletedCounter = Counter.builder("sessions.cleanup.deleted")
            .description("Number of old sessions permanently deleted")
            .register(meterRegistry);
    }

    /**
     * Scheduled task to clean up expired sessions.
     * Runs every 15 minutes to invalidate sessions that have passed their expiration time.
     */
    @Scheduled(fixedRate = 900000) // 15 minutes
    @Transactional
    public void cleanupExpiredSessions() {
        if (!cleanupEnabled) {
            logger.debug("Session cleanup is disabled, skipping expired session cleanup");
            return;
        }

        try {
            logger.debug("Starting cleanup of expired sessions");
            
            int expiredCount = sessionRepository.invalidateExpiredSessions();
            
            if (expiredCount > 0) {
                logger.info("Cleaned up {} expired sessions", expiredCount);
                expiredSessionsCleanedCounter.increment(expiredCount);
            } else {
                logger.debug("No expired sessions found for cleanup");
            }
            
        } catch (Exception e) {
            logger.error("Error during expired session cleanup", e);
        }
    }

    /**
     * Scheduled task to clean up inactive sessions.
     * Runs every hour to invalidate sessions that haven't been accessed for a long time.
     */
    @Scheduled(fixedRate = 3600000) // 1 hour
    @Transactional
    public void cleanupInactiveSessions() {
        if (!cleanupEnabled) {
            logger.debug("Session cleanup is disabled, skipping inactive session cleanup");
            return;
        }

        try {
            logger.debug("Starting cleanup of inactive sessions (threshold: {} hours)", inactiveThresholdHours);
            
            LocalDateTime cutoffTime = LocalDateTime.now().minusHours(inactiveThresholdHours);
            int inactiveCount = sessionRepository.invalidateInactiveSessions(cutoffTime);
            
            if (inactiveCount > 0) {
                logger.info("Cleaned up {} inactive sessions (not accessed for {} hours)", 
                    inactiveCount, inactiveThresholdHours);
                inactiveSessionsCleanedCounter.increment(inactiveCount);
            } else {
                logger.debug("No inactive sessions found for cleanup");
            }
            
        } catch (Exception e) {
            logger.error("Error during inactive session cleanup", e);
        }
    }

    /**
     * Scheduled task to permanently delete old inactive sessions.
     * Runs daily to remove old session records from the database.
     */
    @Scheduled(cron = "0 0 2 * * ?") // Daily at 2 AM
    @Transactional
    public void deleteOldSessions() {
        if (!cleanupEnabled) {
            logger.debug("Session cleanup is disabled, skipping old session deletion");
            return;
        }

        try {
            logger.debug("Starting deletion of old inactive sessions (threshold: {} days)", deletionThresholdDays);
            
            LocalDateTime cutoffTime = LocalDateTime.now().minusDays(deletionThresholdDays);
            int deletedCount = sessionRepository.deleteOldInactiveSessions(cutoffTime);
            
            if (deletedCount > 0) {
                logger.info("Permanently deleted {} old inactive sessions (older than {} days)", 
                    deletedCount, deletionThresholdDays);
                oldSessionsDeletedCounter.increment(deletedCount);
            } else {
                logger.debug("No old inactive sessions found for deletion");
            }
            
        } catch (Exception e) {
            logger.error("Error during old session deletion", e);
        }
    }

    /**
     * Manual cleanup method that can be called programmatically.
     * Performs all cleanup operations immediately.
     * 
     * @return cleanup statistics
     */
    @Transactional
    public SessionCleanupStats performManualCleanup() {
        if (!cleanupEnabled) {
            logger.warn("Session cleanup is disabled, manual cleanup aborted");
            return new SessionCleanupStats(0, 0, 0);
        }

        logger.info("Performing manual session cleanup");
        
        try {
            // Clean up expired sessions
            int expiredCount = sessionRepository.invalidateExpiredSessions();
            if (expiredCount > 0) {
                expiredSessionsCleanedCounter.increment(expiredCount);
            }

            // Clean up inactive sessions
            LocalDateTime inactiveCutoff = LocalDateTime.now().minusHours(inactiveThresholdHours);
            int inactiveCount = sessionRepository.invalidateInactiveSessions(inactiveCutoff);
            if (inactiveCount > 0) {
                inactiveSessionsCleanedCounter.increment(inactiveCount);
            }

            // Delete old sessions
            LocalDateTime deletionCutoff = LocalDateTime.now().minusDays(deletionThresholdDays);
            int deletedCount = sessionRepository.deleteOldInactiveSessions(deletionCutoff);
            if (deletedCount > 0) {
                oldSessionsDeletedCounter.increment(deletedCount);
            }

            SessionCleanupStats stats = new SessionCleanupStats(expiredCount, inactiveCount, deletedCount);
            logger.info("Manual cleanup completed: {}", stats);
            
            return stats;
            
        } catch (Exception e) {
            logger.error("Error during manual session cleanup", e);
            throw new RuntimeException("Manual session cleanup failed", e);
        }
    }

    /**
     * Get current cleanup configuration.
     * 
     * @return cleanup configuration details
     */
    public SessionCleanupConfig getCleanupConfig() {
        return new SessionCleanupConfig(
            cleanupEnabled,
            inactiveThresholdHours,
            deletionThresholdDays
        );
    }

    /**
     * Data class for cleanup statistics.
     */
    public static class SessionCleanupStats {
        private final int expiredSessionsCleaned;
        private final int inactiveSessionsCleaned;
        private final int oldSessionsDeleted;

        public SessionCleanupStats(int expiredSessionsCleaned, int inactiveSessionsCleaned, int oldSessionsDeleted) {
            this.expiredSessionsCleaned = expiredSessionsCleaned;
            this.inactiveSessionsCleaned = inactiveSessionsCleaned;
            this.oldSessionsDeleted = oldSessionsDeleted;
        }

        public int getExpiredSessionsCleaned() { return expiredSessionsCleaned; }
        public int getInactiveSessionsCleaned() { return inactiveSessionsCleaned; }
        public int getOldSessionsDeleted() { return oldSessionsDeleted; }

        @Override
        public String toString() {
            return String.format("SessionCleanupStats{expired=%d, inactive=%d, deleted=%d}", 
                expiredSessionsCleaned, inactiveSessionsCleaned, oldSessionsDeleted);
        }
    }

    /**
     * Data class for cleanup configuration.
     */
    public static class SessionCleanupConfig {
        private final boolean enabled;
        private final int inactiveThresholdHours;
        private final int deletionThresholdDays;

        public SessionCleanupConfig(boolean enabled, int inactiveThresholdHours, int deletionThresholdDays) {
            this.enabled = enabled;
            this.inactiveThresholdHours = inactiveThresholdHours;
            this.deletionThresholdDays = deletionThresholdDays;
        }

        public boolean isEnabled() { return enabled; }
        public int getInactiveThresholdHours() { return inactiveThresholdHours; }
        public int getDeletionThresholdDays() { return deletionThresholdDays; }

        @Override
        public String toString() {
            return String.format("SessionCleanupConfig{enabled=%s, inactiveThreshold=%dh, deletionThreshold=%dd}", 
                enabled, inactiveThresholdHours, deletionThresholdDays);
        }
    }
}