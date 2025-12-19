package com.example.userauthentication.dto;

import java.time.LocalDateTime;

/**
 * DTO for user registration responses.
 * Contains user information returned after successful registration.
 * 
 * Requirements: 1.1, 1.5
 */
public class UserRegistrationResponse {

    private Long id;
    private String email;
    private boolean emailVerified;
    private LocalDateTime createdAt;
    private String message;

    // Default constructor
    public UserRegistrationResponse() {}

    // Constructor
    public UserRegistrationResponse(Long id, String email, boolean emailVerified, LocalDateTime createdAt, String message) {
        this.id = id;
        this.email = email;
        this.emailVerified = emailVerified;
        this.createdAt = createdAt;
        this.message = message;
    }

    // Static factory method for successful registration
    public static UserRegistrationResponse success(Long id, String email, boolean emailVerified, LocalDateTime createdAt) {
        return new UserRegistrationResponse(
            id, 
            email, 
            emailVerified, 
            createdAt, 
            "Registration successful. Please check your email to verify your account."
        );
    }

    // Getters and Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return "UserRegistrationResponse{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", emailVerified=" + emailVerified +
                ", createdAt=" + createdAt +
                ", message='" + message + '\'' +
                '}';
    }
}