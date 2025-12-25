package com.example.userauthentication.dto;

import java.time.LocalDateTime;

/**
 * DTO for user login responses.
 * Contains authentication tokens and user information returned after successful login.
 * 
 * Requirements: 2.1, 2.4
 */
public class LoginResponse {

    private Long userId;
    private String email;
    private String accessToken;
    private String refreshToken;
    private LocalDateTime loginTime;
    private String message;

    // Default constructor
    public LoginResponse() {}

    // Constructor
    public LoginResponse(Long userId, String email, String accessToken, String refreshToken, 
                        LocalDateTime loginTime, String message) {
        this.userId = userId;
        this.email = email;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.loginTime = loginTime;
        this.message = message;
    }

    // Static factory method for successful login
    public static LoginResponse success(Long userId, String email, String accessToken, 
                                       String refreshToken, LocalDateTime loginTime) {
        return new LoginResponse(
            userId, 
            email, 
            accessToken, 
            refreshToken, 
            loginTime, 
            "Login successful"
        );
    }

    // Getters and Setters
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

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public LocalDateTime getLoginTime() {
        return loginTime;
    }

    public void setLoginTime(LocalDateTime loginTime) {
        this.loginTime = loginTime;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    @Override
    public String toString() {
        return "LoginResponse{" +
                "userId=" + userId +
                ", email='" + email + '\'' +
                ", accessToken='[PROTECTED]'" +
                ", refreshToken='[PROTECTED]'" +
                ", loginTime=" + loginTime +
                ", message='" + message + '\'' +
                '}';
    }
}