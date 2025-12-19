package com.example.userauthentication.repository;

import com.example.userauthentication.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for PasswordResetToken entity operations.
 * Provides methods for token management and cleanup.
 */
@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, String> {

    /**
     * Find a password reset token by token string.
     * 
     * @param token the token string
     * @return Optional containing the token if found
     */
    Optional<PasswordResetToken> findByToken(String token);

    /**
     * Find all valid (unused and not expired) tokens for a user.
     * 
     * @param userId the user ID
     * @param now current timestamp
     * @return list of valid tokens
     */
    @Query("SELECT t FROM PasswordResetToken t WHERE t.userId = :userId AND t.used = false AND t.expiresAt > :now")
    List<PasswordResetToken> findValidTokensByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    /**
     * Find all tokens for a specific user.
     * 
     * @param userId the user ID
     * @return list of all tokens for the user
     */
    List<PasswordResetToken> findByUserId(Long userId);

    /**
     * Delete all expired tokens.
     * 
     * @param now current timestamp
     * @return number of deleted tokens
     */
    @Modifying
    @Query("DELETE FROM PasswordResetToken t WHERE t.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") LocalDateTime now);

    /**
     * Delete all used tokens older than specified date.
     * 
     * @param cutoffDate the cutoff date
     * @return number of deleted tokens
     */
    @Modifying
    @Query("DELETE FROM PasswordResetToken t WHERE t.used = true AND t.usedAt < :cutoffDate")
    int deleteUsedTokensOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Mark all existing tokens for a user as used (invalidate them).
     * This is useful when issuing a new token to prevent multiple active tokens.
     * 
     * @param userId the user ID
     * @param now current timestamp
     * @return number of updated tokens
     */
    @Modifying
    @Query("UPDATE PasswordResetToken t SET t.used = true, t.usedAt = :now WHERE t.userId = :userId AND t.used = false")
    int invalidateExistingTokensForUser(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    /**
     * Count valid tokens for a user.
     * 
     * @param userId the user ID
     * @param now current timestamp
     * @return count of valid tokens
     */
    @Query("SELECT COUNT(t) FROM PasswordResetToken t WHERE t.userId = :userId AND t.used = false AND t.expiresAt > :now")
    long countValidTokensByUserId(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    /**
     * Check if a token exists and is valid.
     * 
     * @param token the token string
     * @param now current timestamp
     * @return true if token exists and is valid
     */
    @Query("SELECT COUNT(t) > 0 FROM PasswordResetToken t WHERE t.token = :token AND t.used = false AND t.expiresAt > :now")
    boolean existsValidToken(@Param("token") String token, @Param("now") LocalDateTime now);
}