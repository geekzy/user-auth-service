package com.example.userauthentication.service;

/**
 * Service interface for email operations.
 * Handles sending verification emails and other email notifications.
 * 
 * Requirements: 1.5
 */
public interface EmailService {

    /**
     * Sends an email verification message to the specified email address.
     * 
     * @param email the recipient email address
     * @param verificationToken the verification token to include in the email
     */
    void sendVerificationEmail(String email, String verificationToken);

    /**
     * Sends a password reset email to the specified email address.
     * 
     * @param email the recipient email address
     * @param resetToken the password reset token to include in the email
     */
    void sendPasswordResetEmail(String email, String resetToken);

    /**
     * Sends a security notification email for new device login.
     * 
     * @param email the recipient email address
     * @param deviceInfo information about the new device
     * @param loginTime the time of the login
     */
    void sendNewDeviceNotification(String email, String deviceInfo, String loginTime);
}