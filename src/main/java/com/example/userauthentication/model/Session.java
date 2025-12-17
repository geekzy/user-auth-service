package com.example.userauthentication.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * Session entity representing an authenticated user session.
 * Includes automatic expiration handling and lifecycle management.
 */
@Entity
@Table(name = "sessions", indexes = {
    @Index(name = "idx_sessions_user_id", columnList = "userId"),
    @Index(name = "idx_sessions_expires_at", columnList = "expiresAt"),
    @Index(name = "idx_sessions_last_accessed_at", columnList = "lastAccessedAt"),
    @Index(name = "idx_sessions_is_active", columnList = "isActive"),
    @Index(name = "idx_sessions_cleanup", columnList = "expiresAt, isActive")
})
public class Session {

    @Id
    @Column(name = "id", length = 255)
    @NotBlank(message = "Session ID is required")
    private String id;

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

    @Column(name = "last_accessed_at", nullable = false)
    @NotNull(message = "Last accessed time is required")
    private LocalDateTime lastAccessedAt;

    @Column(name = "ip_address", length = 45) // IPv6 compatible
    @Size(max = 45, message = "IP address must not exceed 45 characters")
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    @Size(max = 2000, message = "User agent must not exceed 2000 characters")
    private String userAgent;

    @Column(name = "is_active", nullable = false)
    @NotNull(message = "Active status is required")
    private Boolean isActive = true;

    // JPA requires a default constructor
    public Session() {}

    /**
     * Constructor for creating a new session.
     * @param userId the ID of the user this session belongs to
     * @param timeoutMinutes session timeout in minutes
     * @param ipAddress client IP address
     * @param userAgent client user agent string
     */
    public Session(Long userId, int timeoutMinutes, String ipAddress, String userAgent) {
        this.id = generateSessionId();
        this.userId = userId;
        this.lastAccessedAt = LocalDateTime.now();
        this.expiresAt = LocalDateTime.now().plusMinutes(timeoutMinutes);
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
        this.isActive = true;
    }

    /**
     * Generates a cryptographically secure session ID.
     * @return a unique session ID
     */
    private String generateSessionId() {
        return UUID.randomUUID().toString().replace("-", "") + 
               System.currentTimeMillis() + 
               UUID.randomUUID().toString().replace("-", "");
    }

    // Getters and Setters
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public LocalDateTime getLastAccessedAt() {
        return lastAccessedAt;
    }

    public void setLastAccessedAt(LocalDateTime lastAccessedAt) {
        this.lastAccessedAt = lastAccessedAt;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    // Business logic methods

    /**
     * Checks if the session is currently valid (active and not expired).
     * @return true if the session is valid
     */
    public boolean isValid() {
        return isActive && LocalDateTime.now().isBefore(expiresAt);
    }

    /**
     * Checks if the session has expired.
     * @return true if the session has expired
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Extends the session by the specified number of minutes from the current time.
     * Also updates the last accessed timestamp.
     * @param extensionMinutes number of minutes to extend the session
     */
    public void extendSession(int extensionMinutes) {
        this.lastAccessedAt = LocalDateTime.now();
        this.expiresAt = LocalDateTime.now().plusMinutes(extensionMinutes);
    }

    /**
     * Updates the last accessed timestamp to the current time.
     * This is called on each request to track session activity.
     */
    public void updateLastAccessed() {
        this.lastAccessedAt = LocalDateTime.now();
    }

    /**
     * Invalidates the session by marking it as inactive.
     * This is typically called during logout.
     */
    public void invalidate() {
        this.isActive = false;
    }

    /**
     * Checks if the session belongs to the specified user.
     * @param userId the user ID to check
     * @return true if the session belongs to the user
     */
    public boolean belongsToUser(Long userId) {
        return Objects.equals(this.userId, userId);
    }

    /**
     * Gets the remaining time in minutes before the session expires.
     * @return remaining minutes, or 0 if already expired
     */
    public long getRemainingMinutes() {
        if (isExpired()) {
            return 0;
        }
        return java.time.Duration.between(LocalDateTime.now(), expiresAt).toMinutes();
    }

    // JPA Lifecycle callbacks

    /**
     * Called before persisting the entity.
     * Ensures the session has a valid ID and timestamps.
     */
    @PrePersist
    protected void onCreate() {
        if (id == null || id.trim().isEmpty()) {
            id = generateSessionId();
        }
        if (lastAccessedAt == null) {
            lastAccessedAt = LocalDateTime.now();
        }
        if (isActive == null) {
            isActive = true;
        }
    }

    /**
     * Called before updating the entity.
     * Validates that the session is still in a consistent state.
     */
    @PreUpdate
    protected void onUpdate() {
        // Automatically mark as inactive if expired
        if (isExpired() && isActive) {
            isActive = false;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Session session = (Session) o;
        return Objects.equals(id, session.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "Session{" +
                "id='" + id + '\'' +
                ", userId=" + userId +
                ", createdAt=" + createdAt +
                ", expiresAt=" + expiresAt +
                ", lastAccessedAt=" + lastAccessedAt +
                ", ipAddress='" + ipAddress + '\'' +
                ", isActive=" + isActive +
                '}';
    }
}