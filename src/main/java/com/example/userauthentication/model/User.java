package com.example.userauthentication.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * User entity representing a registered user in the authentication system.
 * Includes validation constraints and database mappings for secure user management.
 */
@Entity
@Table(name = "users", indexes = {
    @Index(name = "idx_users_email", columnList = "email"),
    @Index(name = "idx_users_email_verified", columnList = "emailVerified"),
    @Index(name = "idx_users_locked_until", columnList = "lockedUntil"),
    @Index(name = "idx_users_created_at", columnList = "createdAt"),
    @Index(name = "idx_users_last_login_at", columnList = "lastLoginAt")
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "email", nullable = false, unique = true, length = 255)
    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid", regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    @NotBlank(message = "Password hash is required")
    @Size(min = 60, max = 255, message = "Password hash must be between 60 and 255 characters")
    private String passwordHash;

    @Column(name = "email_verified", nullable = false)
    @NotNull(message = "Email verified status is required")
    private Boolean emailVerified = false;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    @Column(name = "failed_login_attempts", nullable = false)
    @Min(value = 0, message = "Failed login attempts cannot be negative")
    @Max(value = 100, message = "Failed login attempts cannot exceed 100")
    private Integer failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "updated_at", nullable = false)
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    // Default constructor
    public User() {}

    // Constructor for creating new users
    public User(String email, String passwordHash) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.emailVerified = false;
        this.failedLoginAttempts = 0;
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

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(LocalDateTime lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public Integer getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(Integer failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public LocalDateTime getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(LocalDateTime lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    // Business logic methods
    
    /**
     * Checks if the user account is currently locked.
     * @return true if the account is locked and the lock period hasn't expired
     */
    public boolean isAccountLocked() {
        return lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
    }

    /**
     * Increments the failed login attempts counter.
     */
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts = (this.failedLoginAttempts == null) ? 1 : this.failedLoginAttempts + 1;
    }

    /**
     * Resets the failed login attempts counter to zero.
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lockedUntil = null;
    }

    /**
     * Locks the account for the specified duration in minutes.
     * @param lockDurationMinutes the duration to lock the account
     */
    public void lockAccount(int lockDurationMinutes) {
        this.lockedUntil = LocalDateTime.now().plusMinutes(lockDurationMinutes);
    }

    /**
     * Updates the last login timestamp to the current time.
     */
    public void updateLastLoginTimestamp() {
        this.lastLoginAt = LocalDateTime.now();
    }

    /**
     * Validates password strength according to security requirements.
     * @param password the plain text password to validate
     * @return true if password meets strength requirements
     */
    public static boolean isPasswordStrong(String password) {
        if (password == null || password.length() < 8) {
            return false;
        }
        
        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch -> "!@#$%^&*()_+-=[]{}|;:,.<>?".indexOf(ch) >= 0);
        
        return hasUpper && hasLower && hasDigit && hasSpecial;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(id, user.id) && Objects.equals(email, user.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, email);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", email='" + email + '\'' +
                ", emailVerified=" + emailVerified +
                ", createdAt=" + createdAt +
                ", lastLoginAt=" + lastLoginAt +
                ", failedLoginAttempts=" + failedLoginAttempts +
                ", lockedUntil=" + lockedUntil +
                '}';
    }
}