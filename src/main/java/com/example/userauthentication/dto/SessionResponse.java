package com.example.userauthentication.dto;

import java.time.LocalDateTime;

/**
 * DTO for session validation responses.
 * Contains session information and validation status.
 * 
 * Requirements: 6.1, 6.2
 */
public class SessionResponse {

    private boolean valid;
    private Long userId;
    private String email;
    private LocalDateTime lastAccessed;
    private LocalDateTime expiresAt;
    private String message;

    // Default constructor
    public SessionResponse() {}

    // Constructor
    public SessionResponse(boolean valid, Long userId, String email, 
                          LocalDateTime lastAccessed, LocalDateTime expiresAt, String message) {
        this.valid = valid;
        this.userId = userId;
        this.email = email;
        this.lastAccessed = lastAccessed;
        this.expiresAt = expiresAt;
        this.message = message;
    }

    // Static factory methods
    public static SessionResponse valid(Long userId, String email, 
                                       LocalDateTime lastAccessed, LocalDateTime expiresAt) {
        return new SessionResponse(true, userId, email, lastAccessed, expiresAt, "Session is valid");
    }

    public static SessionResponse invalid(String message) {
        return new SessionResponse(false, null, null, null, null, message);
    }

    // Getters and Setters
    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public LocalDateTime getLastAccessed() {
        return lastAccessed;
    }

    public void setLastAccessed(LocalDateTime lastAccessed) {
        this.lastAccessed = lastAccessed;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return "SessionResponse{" +
                "valid=" + valid +
                ", userId=" + userId +
                ", email='" + email + '\'' +
                ", lastAccessed=" + lastAccessed +
                ", expiresAt=" + expiresAt +
                ", message='" + message + '\'' +
                '}';
    }
}