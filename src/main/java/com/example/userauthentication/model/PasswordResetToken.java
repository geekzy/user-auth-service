package com.example.userauthentication.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.hibernate.annotations.CreationTimestamp;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Objects;

/**
 * Password reset token entity for secure password recovery.
 * Implements single-use tokens with automatic expiration.
 */
@Entity
@Table(name = "password_reset_tokens", indexes = {
    @Index(name = "idx_password_reset_tokens_user_id", columnList = "userId"),
    @Index(name = "idx_password_reset_tokens_expires_at", columnList = "expiresAt"),
    @Index(name = "idx_password_reset_tokens_used", columnList = "used"),
    @Index(name = "idx_password_reset_tokens_cleanup", columnList = "expiresAt, used")
})
public class PasswordResetToken {

    @Id
    @Column(name = "token", length = 255)
    @NotBlank(message = "Token is required")
    @Size(min = 32, max = 255, message = "Token must be between 32 and 255 characters")
    private String token;

    @Column(name = "user_id", nullable = false)
    @NotNull(message = "User ID is required")
    private Long userId;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "expires_at", nullable = false)
    @NotNull(message = "Expiration time is required")
    @Future(message = "Expiration time must be in the future")
    private LocalDateTime expiresAt;

    @Column(name = "used", nullable = false)
    @NotNull(message = "Used status is required")
    private Boolean used = false;

    @Column(name = "used_at")
    private LocalDateTime usedAt;

    // JPA requires a default constructor
    public PasswordResetToken() {}

    /**
     * Constructor for creating a new password reset token.
     * @param userId the ID of the user this token belongs to
     * @param expirationMinutes token expiration time in minutes
     */
    public PasswordResetToken(Long userId, int expirationMinutes) {
        this.token = generateSecureToken();
        this.userId = userId;
        this.expiresAt = LocalDateTime.now().plusMinutes(expirationMinutes);
        this.used = false;
    }

    /**
     * Generates a cryptographically secure random token.
     * Uses 256 bits of entropy for maximum security.
     * @return a secure random token string
     */
    private String generateSecureToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(tokenBytes);
        
        // Encode to URL-safe Base64 and remove padding
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        
        // Add timestamp component for additional uniqueness
        long timestamp = System.currentTimeMillis();
        return token + Long.toString(timestamp, 36);
    }

    // Getters and Setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Boolean getUsed() {
        return used;
    }

    public void setUsed(Boolean used) {
        this.used = used;
    }

    public LocalDateTime getUsedAt() {
        return usedAt;
    }

    public void setUsedAt(LocalDateTime usedAt) {
        this.usedAt = usedAt;
    }

    // Business logic methods

    /**
     * Checks if the token is currently valid (not used and not expired).
     * @return true if the token is valid and can be used
     */
    public boolean isValid() {
        return !used && LocalDateTime.now().isBefore(expiresAt);
    }

    /**
     * Checks if the token has expired.
     * @return true if the token has expired
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Checks if the token has already been used.
     * @return true if the token has been used
     */
    public boolean isUsed() {
        return used != null && used;
    }

    /**
     * Marks the token as used and records the usage timestamp.
     * This enforces single-use behavior.
     */
    public void markAsUsed() {
        this.used = true;
        this.usedAt = LocalDateTime.now();
    }

    /**
     * Checks if the token belongs to the specified user.
     * @param userId the user ID to check
     * @return true if the token belongs to the user
     */
    public boolean belongsToUser(Long userId) {
        return Objects.equals(this.userId, userId);
    }

    /**
     * Gets the remaining time in minutes before the token expires.
     * @return remaining minutes, or 0 if already expired
     */
    public long getRemainingMinutes() {
        if (isExpired()) {
            return 0;
        }
        return java.time.Duration.between(LocalDateTime.now(), expiresAt).toMinutes();
    }

    /**
     * Validates the token for password reset usage.
     * Checks if token is valid, not expired, not used, and belongs to the user.
     * @param userId the user ID attempting to use the token
     * @return true if the token can be used for password reset
     */
    public boolean canBeUsedForPasswordReset(Long userId) {
        return isValid() && belongsToUser(userId) && !isUsed() && !isExpired();
    }

    // JPA Lifecycle callbacks

    /**
     * Called before persisting the entity.
     * Ensures the token has required values.
     */
    @PrePersist
    protected void onCreate() {
        if (token == null || token.trim().isEmpty()) {
            token = generateSecureToken();
        }
        if (used == null) {
            used = false;
        }
    }

    /**
     * Called before updating the entity.
     * Validates state transitions.
     */
    @PreUpdate
    protected void onUpdate() {
        // If marking as used, ensure usedAt timestamp is set
        if (used && usedAt == null) {
            usedAt = LocalDateTime.now();
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PasswordResetToken that = (PasswordResetToken) o;
        return Objects.equals(token, that.token);
    }

    @Override
    public int hashCode() {
        return Objects.hash(token);
    }

    @Override
    public String toString() {
        return "PasswordResetToken{" +
                "token='" + (token != null ? token.substring(0, Math.min(8, token.length())) + "..." : "null") + '\'' +
                ", userId=" + userId +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                ", used=" + used +
                ", usedAt=" + usedAt +
                '}';
    }
}