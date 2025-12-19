package com.example.userauthentication.repository;

import com.example.userauthentication.model.User;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import jakarta.persistence.QueryHint;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * Repository interface for User entity operations.
 * Provides optimized queries with caching and performance monitoring for user management.
 * 
 * Requirements: 1.1, 1.2, 2.4
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by email address with caching enabled.
     * Uses query hints for performance optimization.
     * 
     * @param email the email address to search for
     * @return Optional containing the user if found
     */
    @Cacheable(value = "users", key = "#email", unless = "#result == null")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    Optional<User> findByEmail(String email);

    /**
     * Check if user exists by email with caching.
     * 
     * @param email the email address to check
     * @return true if user exists with this email
     */
    @Cacheable(value = "userExists", key = "#email")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    boolean existsByEmail(String email);

    /**
     * Update last login timestamp for user with optimized query.
     * Uses bulk update for better performance.
     * 
     * @param userId the user ID to update
     * @param loginTime the new login timestamp
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime, u.updatedAt = CURRENT_TIMESTAMP WHERE u.id = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void updateLastLoginTime(@Param("userId") Long userId, @Param("loginTime") LocalDateTime loginTime);

    /**
     * Increment failed login attempts with optimized bulk update.
     * 
     * @param userId the user ID to update
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1, u.updatedAt = CURRENT_TIMESTAMP WHERE u.id = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void incrementFailedLoginAttempts(@Param("userId") Long userId);

    /**
     * Reset failed login attempts to zero with optimized bulk update.
     * 
     * @param userId the user ID to update
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.lockedUntil = null, u.updatedAt = CURRENT_TIMESTAMP WHERE u.id = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void resetFailedLoginAttempts(@Param("userId") Long userId);

    /**
     * Lock user account until specified time with optimized bulk update.
     * 
     * @param userId the user ID to lock
     * @param lockUntil the timestamp until which the account should be locked
     */
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :lockUntil, u.updatedAt = CURRENT_TIMESTAMP WHERE u.id = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void lockUserAccount(@Param("userId") Long userId, @Param("lockUntil") LocalDateTime lockUntil);

    /**
     * Unlock user account with optimized bulk update.
     * 
     * @param userId the user ID to unlock
     */
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = null, u.failedLoginAttempts = 0, u.updatedAt = CURRENT_TIMESTAMP WHERE u.id = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void unlockUserAccount(@Param("userId") Long userId);

    /**
     * Update user password with optimized bulk update.
     * 
     * @param userId the user ID to update
     * @param passwordHash the new password hash
     */
    @Modifying
    @Query("UPDATE User u SET u.passwordHash = :passwordHash, u.updatedAt = CURRENT_TIMESTAMP WHERE u.id = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void updatePassword(@Param("userId") Long userId, @Param("passwordHash") String passwordHash);

    /**
     * Mark email as verified with optimized bulk update.
     * 
     * @param userId the user ID to update
     */
    @Modifying
    @Query("UPDATE User u SET u.emailVerified = true, u.updatedAt = CURRENT_TIMESTAMP WHERE u.id = :userId")
    @QueryHints(@QueryHint(name = "org.hibernate.flushMode", value = "COMMIT"))
    void markEmailAsVerified(@Param("userId") Long userId);

    /**
     * Find users with expired account locks for cleanup.
     * Used for maintenance operations.
     * 
     * @return list of users whose lock period has expired
     */
    @Query("SELECT u FROM User u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil < CURRENT_TIMESTAMP")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    java.util.List<User> findUsersWithExpiredLocks();

    /**
     * Count users registered within a specific time period.
     * Used for analytics and monitoring.
     * 
     * @param startDate the start of the time period
     * @param endDate the end of the time period
     * @return count of users registered in the period
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.createdAt BETWEEN :startDate AND :endDate")
    @QueryHints(@QueryHint(name = "org.hibernate.cacheable", value = "true"))
    long countUsersRegisteredBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);
}