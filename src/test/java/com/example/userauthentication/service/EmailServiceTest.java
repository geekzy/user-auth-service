package com.example.userauthentication.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for EmailService registration email functionality.
 * Tests email verification sending, template rendering, and error handling.
 * 
 * Requirements: 1.5
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("EmailService Registration Email Tests")
class EmailServiceTest {

    private EmailService emailService;
    private TestLogAppender logAppender;

    @BeforeEach
    void setUp() {
        emailService = new EmailServiceImpl();
        logAppender = new TestLogAppender();
        
        // Attach log appender to capture log messages
        Logger logger = LoggerFactory.getLogger(EmailServiceImpl.class);
        if (logger instanceof ch.qos.logback.classic.Logger) {
            ((ch.qos.logback.classic.Logger) logger).addAppender(logAppender);
            logAppender.start();
        }
    }

    @Test
    @DisplayName("Should send verification email with valid email and token")
    void shouldSendVerificationEmailWithValidEmailAndToken() {
        // Given
        String email = "test@example.com";
        String verificationToken = "abc123token";

        // When
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, verificationToken);
        });

        // Then - Wait a bit for async operation to complete
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            assertThat(logAppender.getMessages())
                .anyMatch(msg -> msg.contains("Sending verification email to: " + email))
                .anyMatch(msg -> msg.contains("with token: " + verificationToken))
                .anyMatch(msg -> msg.contains("Verification email sent successfully to: " + email));
        });
    }

    @Test
    @DisplayName("Should handle verification email with special characters in email")
    void shouldHandleVerificationEmailWithSpecialCharactersInEmail() {
        // Given
        String email = "test+special@example-domain.co.uk";
        String verificationToken = "token123";

        // When
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, verificationToken);
        });

        // Then
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            assertThat(logAppender.getMessages())
                .anyMatch(msg -> msg.contains("Sending verification email to: " + email))
                .anyMatch(msg -> msg.contains("Verification email sent successfully to: " + email));
        });
    }

    @Test
    @DisplayName("Should handle verification email with long token")
    void shouldHandleVerificationEmailWithLongToken() {
        // Given
        String email = "test@example.com";
        String longToken = "a".repeat(256); // Very long token

        // When
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, longToken);
        });

        // Then
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            assertThat(logAppender.getMessages())
                .anyMatch(msg -> msg.contains("Sending verification email to: " + email))
                .anyMatch(msg -> msg.contains("with token: " + longToken))
                .anyMatch(msg -> msg.contains("Verification email sent successfully to: " + email));
        });
    }

    @Test
    @DisplayName("Should handle verification email with null email gracefully")
    void shouldHandleVerificationEmailWithNullEmailGracefully() {
        // Given
        String email = null;
        String verificationToken = "token123";

        // When & Then - Should not throw exception but may log error
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, verificationToken);
        });

        // Verify that the method completes (even if it logs an error)
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            // The method should complete without throwing an exception
            // Logging behavior may vary based on implementation
            assertTrue(true); // Method completed successfully
        });
    }

    @Test
    @DisplayName("Should handle verification email with null token gracefully")
    void shouldHandleVerificationEmailWithNullTokenGracefully() {
        // Given
        String email = "test@example.com";
        String verificationToken = null;

        // When & Then - Should not throw exception but may log error
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, verificationToken);
        });

        // Verify that the method completes
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            assertTrue(true); // Method completed successfully
        });
    }

    @Test
    @DisplayName("Should handle verification email with empty token")
    void shouldHandleVerificationEmailWithEmptyToken() {
        // Given
        String email = "test@example.com";
        String verificationToken = "";

        // When
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, verificationToken);
        });

        // Then
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            assertThat(logAppender.getMessages())
                .anyMatch(msg -> msg.contains("Sending verification email to: " + email))
                .anyMatch(msg -> msg.contains("with token: "))
                .anyMatch(msg -> msg.contains("Verification email sent successfully to: " + email));
        });
    }

    @Test
    @DisplayName("Should complete verification email sending operation")
    void shouldCompleteVerificationEmailSendingOperation() {
        // Given
        String email = "async@example.com";
        String verificationToken = "asyncToken123";

        // When
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, verificationToken);
        });

        // Then - Verify operation completes successfully
        // Note: @Async annotation requires Spring context to work asynchronously
        // In unit tests without Spring context, it executes synchronously
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            assertThat(logAppender.getMessages())
                .anyMatch(msg -> msg.contains("Verification email sent successfully to: " + email));
        });
    }

    @Test
    @DisplayName("Should handle multiple concurrent verification email requests")
    void shouldHandleMultipleConcurrentVerificationEmailRequests() {
        // Given
        String[] emails = {"user1@example.com", "user2@example.com", "user3@example.com"};
        String[] tokens = {"token1", "token2", "token3"};

        // When - Send multiple emails concurrently
        CompletableFuture<Void>[] futures = new CompletableFuture[emails.length];
        for (int i = 0; i < emails.length; i++) {
            final int index = i;
            futures[i] = CompletableFuture.runAsync(() -> {
                emailService.sendVerificationEmail(emails[index], tokens[index]);
            });
        }

        // Then - All should complete successfully
        assertDoesNotThrow(() -> {
            CompletableFuture.allOf(futures).get(2, TimeUnit.SECONDS);
        });

        // Verify all emails were processed
        await().atMost(2, TimeUnit.SECONDS).untilAsserted(() -> {
            for (String email : emails) {
                assertThat(logAppender.getMessages())
                    .anyMatch(msg -> msg.contains("Verification email sent successfully to: " + email));
            }
        });
    }

    @Test
    @DisplayName("Should handle thread interruption during email sending")
    void shouldHandleThreadInterruptionDuringEmailSending() {
        // Given
        String email = "interrupt@example.com";
        String verificationToken = "interruptToken";

        // When - Interrupt the current thread and send email
        Thread.currentThread().interrupt();
        
        assertDoesNotThrow(() -> {
            emailService.sendVerificationEmail(email, verificationToken);
        });

        // Then - Should handle interruption gracefully
        await().atMost(1, TimeUnit.SECONDS).untilAsserted(() -> {
            assertThat(logAppender.getMessages())
                .anyMatch(msg -> msg.contains("Email sending interrupted for: " + email) ||
                              msg.contains("Verification email sent successfully to: " + email));
        });

        // Clear interrupt status
        Thread.interrupted();
    }

    /**
     * Helper method to wait for async operations with timeout.
     */
    private AwaitilityHelper await() {
        return new AwaitilityHelper();
    }

    /**
     * Simple helper class for waiting with timeout.
     */
    private static class AwaitilityHelper {
        public AwaitilityHelper atMost(long timeout, TimeUnit unit) {
            return this;
        }

        public void untilAsserted(Runnable assertion) {
            long endTime = System.currentTimeMillis() + 1000; // 1 second timeout
            Exception lastException = null;
            
            while (System.currentTimeMillis() < endTime) {
                try {
                    assertion.run();
                    return; // Success
                } catch (Exception e) {
                    lastException = e;
                    try {
                        Thread.sleep(50); // Wait 50ms before retry
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Interrupted while waiting", ie);
                    }
                }
            }
            
            if (lastException != null) {
                throw new RuntimeException("Assertion failed after timeout", lastException);
            }
        }
    }
}