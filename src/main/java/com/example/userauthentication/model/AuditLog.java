package com.example.userauthentication.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Audit log entity for tracking security events and user activities.
 * Provides comprehensive logging for security monitoring and compliance.
 */
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_logs_user_id", columnList = "userId"),
    @Index(name = "idx_audit_logs_event_type", columnList = "eventType"),
    @Index(name = "idx_audit_logs_created_at", columnList = "createdAt"),
    @Index(name = "idx_audit_logs_success", columnList = "success"),
    @Index(name = "idx_audit_logs_ip_address", columnList = "ipAddress")
})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id")
    private Long userId; // Nullable for events not tied to specific users

    @Column(name = "event_type", nullable = false, length = 50)
    @NotBlank(message = "Event type is required")
    @Size(max = 50, message = "Event type must not exceed 50 characters")
    private String eventType;

    @Column(name = "event_description", columnDefinition = "TEXT")
    @Size(max = 2000, message = "Event description must not exceed 2000 characters")
    private String eventDescription;

    @Column(name = "ip_address", length = 45) // IPv6 compatible
    @Size(max = 45, message = "IP address must not exceed 45 characters")
    private String ipAddress;

    @Column(name = "user_agent", columnDefinition = "TEXT")
    @Size(max = 2000, message = "User agent must not exceed 2000 characters")
    private String userAgent;

    @Column(name = "success", nullable = false)
    @NotNull(message = "Success status is required")
    private Boolean success;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    // Event type constants
    public static final String EVENT_USER_REGISTRATION = "USER_REGISTRATION";
    public static final String EVENT_USER_LOGIN = "USER_LOGIN";
    public static final String EVENT_USER_LOGOUT = "USER_LOGOUT";
    public static final String EVENT_PASSWORD_RESET_REQUEST = "PASSWORD_RESET_REQUEST";
    public static final String EVENT_PASSWORD_RESET_COMPLETE = "PASSWORD_RESET_COMPLETE";
    public static final String EVENT_ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    public static final String EVENT_ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED";
    public static final String EVENT_EMAIL_VERIFICATION = "EMAIL_VERIFICATION";
    public static final String EVENT_SESSION_EXPIRED = "SESSION_EXPIRED";
    public static final String EVENT_SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY";

    // Default constructor
    public AuditLog() {}

    /**
     * Constructor for creating audit log entries.
     * @param userId the user ID (can be null for system events)
     * @param eventType the type of event
     * @param eventDescription detailed description of the event
     * @param success whether the event was successful
     * @param ipAddress client IP address
     * @param userAgent client user agent
     */
    public AuditLog(Long userId, String eventType, String eventDescription, 
                   Boolean success, String ipAddress, String userAgent) {
        this.userId = userId;
        this.eventType = eventType;
        this.eventDescription = eventDescription;
        this.success = success;
        this.ipAddress = ipAddress;
        this.userAgent = userAgent;
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public String getEventDescription() {
        return eventDescription;
    }

    public void setEventDescription(String eventDescription) {
        this.eventDescription = eventDescription;
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

    public Boolean getSuccess() {
        return success;
    }

    public void setSuccess(Boolean success) {
        this.success = success;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    // Business logic methods

    /**
     * Checks if this audit log entry represents a successful event.
     * @return true if the event was successful
     */
    public boolean isSuccessful() {
        return success != null && success;
    }

    /**
     * Checks if this audit log entry is associated with a specific user.
     * @return true if the log entry has a user ID
     */
    public boolean hasUser() {
        return userId != null;
    }

    /**
     * Checks if this audit log entry represents a security-related event.
     * @return true if the event type indicates a security event
     */
    public boolean isSecurityEvent() {
        return eventType != null && (
            eventType.equals(EVENT_USER_LOGIN) ||
            eventType.equals(EVENT_USER_LOGOUT) ||
            eventType.equals(EVENT_PASSWORD_RESET_REQUEST) ||
            eventType.equals(EVENT_PASSWORD_RESET_COMPLETE) ||
            eventType.equals(EVENT_ACCOUNT_LOCKED) ||
            eventType.equals(EVENT_SUSPICIOUS_ACTIVITY)
        );
    }

    /**
     * Factory method for creating successful audit log entries.
     */
    public static AuditLog success(Long userId, String eventType, String description, 
                                 String ipAddress, String userAgent) {
        return new AuditLog(userId, eventType, description, true, ipAddress, userAgent);
    }

    /**
     * Factory method for creating failed audit log entries.
     */
    public static AuditLog failure(Long userId, String eventType, String description, 
                                 String ipAddress, String userAgent) {
        return new AuditLog(userId, eventType, description, false, ipAddress, userAgent);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuditLog auditLog = (AuditLog) o;
        return Objects.equals(id, auditLog.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Override
    public String toString() {
        return "AuditLog{" +
                "id=" + id +
                ", userId=" + userId +
                ", eventType='" + eventType + '\'' +
                ", eventDescription='" + eventDescription + '\'' +
                ", success=" + success +
                ", createdAt=" + createdAt +
                ", ipAddress='" + ipAddress + '\'' +
                '}';
    }
}