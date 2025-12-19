package com.example.userauthentication.repository;

import com.example.userauthentication.model.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import jakarta.persistence.QueryHint;
import java.time.LocalDateTime;
import java.util.List;

/**
 * Repository interface for AuditLog entity operations.
 * Provides efficient querying and archival capabilities for security event logging.
 * Configured for async logging performance optimization.
 * 
 * Requirements: 3.4, 5.5
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    /**
     * Find audit logs by user ID with pagination for efficient querying.
     * 
     * @param userId the user ID to search for
     * @param pageable pagination parameters
     * @return paginated list of audit logs for the user
     */
    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Page<AuditLog> findByUserIdOrderByCreatedAtDesc(@Param("userId") Long userId, Pageable pageable);

    /**
     * Find audit logs by event type with pagination.
     * 
     * @param eventType the event type to search for
     * @param pageable pagination parameters
     * @return paginated list of audit logs for the event type
     */
    @Query("SELECT a FROM AuditLog a WHERE a.eventType = :eventType ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Page<AuditLog> findByEventTypeOrderByCreatedAtDesc(@Param("eventType") String eventType, Pageable pageable);

    /**
     * Find audit logs by success status with pagination.
     * 
     * @param success the success status to filter by
     * @param pageable pagination parameters
     * @return paginated list of audit logs filtered by success status
     */
    @Query("SELECT a FROM AuditLog a WHERE a.success = :success ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Page<AuditLog> findBySuccessOrderByCreatedAtDesc(@Param("success") Boolean success, Pageable pageable);

    /**
     * Find audit logs within a specific time range with pagination.
     * Optimized for archival and reporting operations.
     * 
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @param pageable pagination parameters
     * @return paginated list of audit logs in the time range
     */
    @Query("SELECT a FROM AuditLog a WHERE a.createdAt BETWEEN :startTime AND :endTime ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Page<AuditLog> findByCreatedAtBetweenOrderByCreatedAtDesc(
        @Param("startTime") LocalDateTime startTime, 
        @Param("endTime") LocalDateTime endTime, 
        Pageable pageable
    );

    /**
     * Find security events (login, logout, password reset, etc.) for a user.
     * 
     * @param userId the user ID to search for
     * @param pageable pagination parameters
     * @return paginated list of security-related audit logs for the user
     */
    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId AND a.eventType IN " +
           "('USER_LOGIN', 'USER_LOGOUT', 'PASSWORD_RESET_REQUEST', 'PASSWORD_RESET_COMPLETE', " +
           "'ACCOUNT_LOCKED', 'SUSPICIOUS_ACTIVITY') ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Page<AuditLog> findSecurityEventsByUserId(@Param("userId") Long userId, Pageable pageable);

    /**
     * Find failed authentication attempts by IP address within a time range.
     * Used for security monitoring and rate limiting.
     * 
     * @param ipAddress the IP address to search for
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @return list of failed authentication attempts from the IP
     */
    @Query("SELECT a FROM AuditLog a WHERE a.ipAddress = :ipAddress AND a.success = false " +
           "AND a.eventType IN ('USER_LOGIN', 'PASSWORD_RESET_REQUEST') " +
           "AND a.createdAt BETWEEN :startTime AND :endTime ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "false"))
    List<AuditLog> findFailedAuthenticationAttemptsByIpAndTimeRange(
        @Param("ipAddress") String ipAddress,
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Find failed login attempts for a specific user within a time range.
     * Used for account locking and security monitoring.
     * 
     * @param userId the user ID to search for
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @return list of failed login attempts for the user
     */
    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId AND a.success = false " +
           "AND a.eventType = 'USER_LOGIN' AND a.createdAt BETWEEN :startTime AND :endTime " +
           "ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "false"))
    List<AuditLog> findFailedLoginAttemptsByUserAndTimeRange(
        @Param("userId") Long userId,
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Count audit logs by event type within a time range.
     * Used for analytics and monitoring dashboards.
     * 
     * @param eventType the event type to count
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @return count of audit logs for the event type in the time range
     */
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.eventType = :eventType " +
           "AND a.createdAt BETWEEN :startTime AND :endTime")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    long countByEventTypeAndTimeRange(
        @Param("eventType") String eventType,
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Count successful vs failed events within a time range.
     * Used for success rate analytics.
     * 
     * @param success the success status to count
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @return count of audit logs with the specified success status in the time range
     */
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.success = :success " +
           "AND a.createdAt BETWEEN :startTime AND :endTime")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    long countBySuccessAndTimeRange(
        @Param("success") Boolean success,
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Find audit logs older than a specified date for archival.
     * Used by cleanup and archival processes.
     * 
     * @param cutoffDate logs older than this date will be returned
     * @param pageable pagination parameters for batch processing
     * @return paginated list of old audit logs for archival
     */
    @Query("SELECT a FROM AuditLog a WHERE a.createdAt < :cutoffDate ORDER BY a.createdAt ASC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "false"))
    Page<AuditLog> findLogsForArchival(@Param("cutoffDate") LocalDateTime cutoffDate, Pageable pageable);

    /**
     * Delete audit logs older than a specified date.
     * Used for permanent cleanup after archival.
     * 
     * @param cutoffDate logs older than this date will be deleted
     * @return number of audit logs that were deleted
     */
    @Modifying
    @Query("DELETE FROM AuditLog a WHERE a.createdAt < :cutoffDate")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    int deleteLogsOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Find recent suspicious activity events for security monitoring.
     * 
     * @param hours number of hours to look back
     * @return list of suspicious activity events in the specified time frame
     */
    @Query("SELECT a FROM AuditLog a WHERE a.eventType = 'SUSPICIOUS_ACTIVITY' " +
           "AND a.createdAt >= :startTime ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "false"))
    List<AuditLog> findRecentSuspiciousActivity(@Param("startTime") LocalDateTime startTime);

    /**
     * Find audit logs by multiple event types with pagination.
     * Used for flexible security event querying.
     * 
     * @param eventTypes list of event types to search for
     * @param pageable pagination parameters
     * @return paginated list of audit logs matching any of the event types
     */
    @Query("SELECT a FROM AuditLog a WHERE a.eventType IN :eventTypes ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Page<AuditLog> findByEventTypesOrderByCreatedAtDesc(
        @Param("eventTypes") List<String> eventTypes, 
        Pageable pageable
    );

    /**
     * Find audit logs by user and event types with time range filtering.
     * Comprehensive query for detailed user activity analysis.
     * 
     * @param userId the user ID to search for
     * @param eventTypes list of event types to include
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @param pageable pagination parameters
     * @return paginated list of matching audit logs
     */
    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId " +
           "AND a.eventType IN :eventTypes " +
           "AND a.createdAt BETWEEN :startTime AND :endTime " +
           "ORDER BY a.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Page<AuditLog> findByUserAndEventTypesAndTimeRange(
        @Param("userId") Long userId,
        @Param("eventTypes") List<String> eventTypes,
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime,
        Pageable pageable
    );

    /**
     * Get audit log statistics for a time period.
     * Returns aggregated data for monitoring dashboards.
     * 
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @return list of objects containing event type and count
     */
    @Query("SELECT a.eventType, COUNT(a), SUM(CASE WHEN a.success = true THEN 1 ELSE 0 END) " +
           "FROM AuditLog a WHERE a.createdAt BETWEEN :startTime AND :endTime " +
           "GROUP BY a.eventType ORDER BY COUNT(a) DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    List<Object[]> getEventStatistics(
        @Param("startTime") LocalDateTime startTime,
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Check if there are any audit logs for a specific user.
     * Used for user data verification and GDPR compliance.
     * 
     * @param userId the user ID to check
     * @return true if there are audit logs for the user
     */
    @Query("SELECT CASE WHEN COUNT(a) > 0 THEN true ELSE false END FROM AuditLog a WHERE a.userId = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    boolean existsByUserId(@Param("userId") Long userId);

    /**
     * Find the most recent audit log for a user and event type.
     * Used for tracking last occurrence of specific events.
     * 
     * @param userId the user ID to search for
     * @param eventType the event type to search for
     * @return the most recent audit log matching the criteria, if any
     */
    @Query("SELECT a FROM AuditLog a WHERE a.userId = :userId AND a.eventType = :eventType " +
           "ORDER BY a.createdAt DESC LIMIT 1")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    AuditLog findMostRecentByUserAndEventType(@Param("userId") Long userId, @Param("eventType") String eventType);
}