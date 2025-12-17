package com.example.userauthentication.repository;

import com.example.userauthentication.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by email address
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if user exists by email
     */
    boolean existsByEmail(String email);

    /**
     * Update last login timestamp for user
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :loginTime WHERE u.id = :userId")
    void updateLastLoginTime(@Param("userId") Long userId, @Param("loginTime") LocalDateTime loginTime);

    /**
     * Increment failed login attempts
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.id = :userId")
    void incrementFailedLoginAttempts(@Param("userId") Long userId);

    /**
     * Reset failed login attempts to zero
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0 WHERE u.id = :userId")
    void resetFailedLoginAttempts(@Param("userId") Long userId);

    /**
     * Lock user account until specified time
     */
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :lockUntil WHERE u.id = :userId")
    void lockUserAccount(@Param("userId") Long userId, @Param("lockUntil") LocalDateTime lockUntil);

    /**
     * Unlock user account
     */
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = null WHERE u.id = :userId")
    void unlockUserAccount(@Param("userId") Long userId);

    /**
     * Update user password
     */
    @Modifying
    @Query("UPDATE User u SET u.passwordHash = :passwordHash WHERE u.id = :userId")
    void updatePassword(@Param("userId") Long userId, @Param("passwordHash") String passwordHash);

    /**
     * Mark email as verified
     */
    @Modifying
    @Query("UPDATE User u SET u.emailVerified = true WHERE u.id = :userId")
    void markEmailAsVerified(@Param("userId") Long userId);
}