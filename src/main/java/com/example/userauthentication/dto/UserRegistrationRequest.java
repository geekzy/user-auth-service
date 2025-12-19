package com.example.userauthentication.dto;

import jakarta.validation.constraints.*;

/**
 * DTO for user registration requests.
 * Contains validation constraints for secure user registration.
 * 
 * Requirements: 1.1, 1.3, 1.4
 */
public class UserRegistrationRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid", regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-=\\[\\]{}|;:,.<>?]).{8,}$",
        message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character"
    )
    private String password;

    @NotBlank(message = "Password confirmation is required")
    private String confirmPassword;

    // Default constructor
    public UserRegistrationRequest() {}

    // Constructor
    public UserRegistrationRequest(String email, String password, String confirmPassword) {
        this.email = email;
        this.password = password;
        this.confirmPassword = confirmPassword;
    }

    // Getters and Setters
    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    /**
     * Validates that password and confirmPassword match.
     * @return true if passwords match
     */
    public boolean isPasswordConfirmed() {
        return password != null && password.equals(confirmPassword);
    }

    @Override
    public String toString() {
        return "UserRegistrationRequest{" +
                "email='" + email + '\'' +
                ", password='[PROTECTED]'" +
                ", confirmPassword='[PROTECTED]'" +
                '}';
    }
}