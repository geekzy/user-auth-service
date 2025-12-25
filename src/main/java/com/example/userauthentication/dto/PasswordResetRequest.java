package com.example.userauthentication.dto;

import jakarta.validation.constraints.*;

/**
 * DTO for password reset requests.
 * Contains validation constraints for secure password reset initiation.
 * 
 * Requirements: 4.1, 4.2
 */
public class PasswordResetRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid", regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;

    // Default constructor
    public PasswordResetRequest() {}

    // Constructor
    public PasswordResetRequest(String email) {
        this.email = email;
    }

    // Getters and Setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "PasswordResetRequest{" +
                "email='" + email + '\'' +
                '}';
    }
}