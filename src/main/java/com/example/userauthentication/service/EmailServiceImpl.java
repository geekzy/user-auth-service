package com.example.userauthentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Implementation of EmailService for sending email notifications.
 * Currently provides a mock implementation that logs email operations.
 * Will be replaced with actual email sending functionality in task 12.
 * 
 * Requirements: 1.5
 */
@Service
public class EmailServiceImpl implements EmailService {

    private static final Logger logger = LoggerFactory.getLogger(EmailServiceImpl.class);

    @Override
    @Async
    public void sendVerificationEmail(String email, String verificationToken) {
        // Mock implementation - logs the email operation
        // This will be replaced with actual email sending in task 12
        logger.info("Sending verification email to: {} with token: {}", email, verificationToken);
        
        // Simulate email sending delay
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Email sending interrupted for: {}", email);
        }
        
        logger.info("Verification email sent successfully to: {}", email);
    }

    @Override
    @Async
    public void sendPasswordResetEmail(String email, String resetToken) {
        // Mock implementation - logs the email operation
        logger.info("Sending password reset email to: {} with token: {}", email, resetToken);
        
        // Simulate email sending delay
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Password reset email sending interrupted for: {}", email);
        }
        
        logger.info("Password reset email sent successfully to: {}", email);
    }

    @Override
    @Async
    public void sendNewDeviceNotification(String email, String deviceInfo, String loginTime) {
        // Mock implementation - logs the email operation
        logger.info("Sending new device notification to: {} for device: {} at time: {}", 
                   email, deviceInfo, loginTime);
        
        // Simulate email sending delay
        try {
            Thread.sleep(100);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("New device notification sending interrupted for: {}", email);
        }
        
        logger.info("New device notification sent successfully to: {}", email);
    }
}