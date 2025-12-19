package com.example.userauthentication.repository;

import com.example.userauthentication.model.Session;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import jakarta.persistence.QueryHint;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Session entity operations.
 * Provides optimized queries with caching and automatic cleanup scheduling.
 * 
 * Requirements: 2.1, 3.1, 6.1, 6.2
 */
@Repository
public interface SessionRepository extends JpaRepository<Session, String> {

    /**
     * Find an active session by ID with caching.
     * 
     * @param sessionId the session ID to search for
     * @return Optional containing the session if found and active
     */
    @Cacheable(value = "sessionCache", key = "#sessionId", unless = "#result == null")
    @Query("SELECT s FROM Session s WHERE s.id = :sessionId AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Optional<Session> findActiveSessionById(@Param("sessionId") String sessionId);

    /**
     * Find all active sessions for a specific user.
     * 
     * @param userId the user ID to search for
     * @return list of active sessions for the user
     */
    @Query("SELECT s FROM Session s WHERE s.userId = :userId AND s.isActive = true ORDER BY s.lastAccessedAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    List<Session> findActiveSessionsByUserId(@Param("userId") Long userId);

    /**
     * Find all sessions for a specific user (active and inactive).
     * 
     * @param userId the user ID to search for
     * @return list of all sessions for the user
     */
    @Query("SELECT s FROM Session s WHERE s.userId = :userId ORDER BY s.lastAccessedAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    List<Session> findAllSessionsByUserId(@Param("userId") Long userId);

    /**
     * Update the last accessed timestamp for a session.
     * 
     * @param sessionId the session ID to update
     * @param lastAccessedAt the new last accessed timestamp
     */
    @Modifying
    @CacheEvict(value = "sessionCache", key = "#sessionId")
    @Query("UPDATE Session s SET s.lastAccessedAt = :lastAccessedAt WHERE s.id = :sessionId AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void updateLastAccessedTime(@Param("sessionId") String sessionId, @Param("lastAccessedAt") LocalDateTime lastAccessedAt);

    /**
     * Extend session expiration time.
     * 
     * @param sessionId the session ID to extend
     * @param newExpirationTime the new expiration timestamp
     */
    @Modifying
    @CacheEvict(value = "sessionCache", key = "#sessionId")
    @Query("UPDATE Session s SET s.expiresAt = :newExpirationTime, s.lastAccessedAt = CURRENT_TIMESTAMP WHERE s.id = :sessionId AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void extendSessionExpiration(@Param("sessionId") String sessionId, @Param("newExpirationTime") LocalDateTime newExpirationTime);

    /**
     * Invalidate a specific session by marking it as inactive.
     * 
     * @param sessionId the session ID to invalidate
     */
    @Modifying
    @CacheEvict(value = "sessionCache", key = "#sessionId")
    @Query("UPDATE Session s SET s.isActive = false WHERE s.id = :sessionId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void invalidateSession(@Param("sessionId") String sessionId);

    /**
     * Invalidate all sessions for a specific user.
     * 
     * @param userId the user ID whose sessions should be invalidated
     */
    @Modifying
    @CacheEvict(value = "sessionCache", allEntries = true)
    @Query("UPDATE Session s SET s.isActive = false WHERE s.userId = :userId AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void invalidateAllUserSessions(@Param("userId") Long userId);

    /**
     * Find expired sessions that need cleanup.
     * Used by the scheduled cleanup task.
     * 
     * @return list of expired sessions
     */
    @Query("SELECT s FROM Session s WHERE s.expiresAt < CURRENT_TIMESTAMP AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "false"))
    List<Session> findExpiredSessions();

    /**
     * Find sessions that haven't been accessed for a specified duration.
     * Used for inactive session cleanup.
     * 
     * @param cutoffTime sessions not accessed since this time will be returned
     * @return list of inactive sessions
     */
    @Query("SELECT s FROM Session s WHERE s.lastAccessedAt < :cutoffTime AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "false"))
    List<Session> findInactiveSessions(@Param("cutoffTime") LocalDateTime cutoffTime);

    /**
     * Batch invalidate expired sessions.
     * More efficient than individual updates for cleanup operations.
     * 
     * @return number of sessions that were invalidated
     */
    @Modifying
    @CacheEvict(value = "sessionCache", allEntries = true)
    @Query("UPDATE Session s SET s.isActive = false WHERE s.expiresAt < CURRENT_TIMESTAMP AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    int invalidateExpiredSessions();

    /**
     * Batch invalidate sessions that haven't been accessed for a specified duration.
     * 
     * @param cutoffTime sessions not accessed since this time will be invalidated
     * @return number of sessions that were invalidated
     */
    @Modifying
    @CacheEvict(value = "sessionCache", allEntries = true)
    @Query("UPDATE Session s SET s.isActive = false WHERE s.lastAccessedAt < :cutoffTime AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    int invalidateInactiveSessions(@Param("cutoffTime") LocalDateTime cutoffTime);

    /**
     * Delete old inactive sessions from the database.
     * Used for permanent cleanup of old session records.
     * 
     * @param cutoffTime sessions older than this time will be deleted
     * @return number of sessions that were deleted
     */
    @Modifying
    @Query("DELETE FROM Session s WHERE s.isActive = false AND s.expiresAt < :cutoffTime")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    int deleteOldInactiveSessions(@Param("cutoffTime") LocalDateTime cutoffTime);

    /**
     * Count active sessions for a specific user.
     * Used for session limit enforcement.
     * 
     * @param userId the user ID to count sessions for
     * @return number of active sessions for the user
     */
    @Query("SELECT COUNT(s) FROM Session s WHERE s.userId = :userId AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    long countActiveSessionsByUserId(@Param("userId") Long userId);

    /**
     * Find sessions by IP address for security monitoring.
     * 
     * @param ipAddress the IP address to search for
     * @param startTime start of the time range
     * @param endTime end of the time range
     * @return list of sessions from the specified IP in the time range
     */
    @Query("SELECT s FROM Session s WHERE s.ipAddress = :ipAddress AND s.createdAt BETWEEN :startTime AND :endTime ORDER BY s.createdAt DESC")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    List<Session> findSessionsByIpAddressAndTimeRange(
        @Param("ipAddress") String ipAddress, 
        @Param("startTime") LocalDateTime startTime, 
        @Param("endTime") LocalDateTime endTime
    );

    /**
     * Find sessions created within a specific time period for analytics.
     * 
     * @param startTime start of the time period
     * @param endTime end of the time period
     * @return count of sessions created in the period
     */
    @Query("SELECT COUNT(s) FROM Session s WHERE s.createdAt BETWEEN :startTime AND :endTime")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    long countSessionsCreatedBetween(@Param("startTime") LocalDateTime startTime, @Param("endTime") LocalDateTime endTime);

    /**
     * Check if a user has any active sessions.
     * 
     * @param userId the user ID to check
     * @return true if the user has at least one active session
     */
    @Query("SELECT CASE WHEN COUNT(s) > 0 THEN true ELSE false END FROM Session s WHERE s.userId = :userId AND s.isActive = true")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    boolean hasActiveSession(@Param("userId") Long userId);
}