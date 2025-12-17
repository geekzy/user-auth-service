package com.example.userauthentication.model;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.LocalDateTime;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Session lifecycle covering creation, extension, expiration scenarios,
 * and cleanup/validation edge cases.
 * Tests Requirements 6.1 (session extension) and 6.2 (session expiration).
 */
@DisplayName("Session Lifecycle Tests")
class SessionLifecycleTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Nested
    @DisplayName("Session Creation Tests")
    class SessionCreationTests {

        @Test
        @DisplayName("Should create valid session with all required fields")
        void shouldCreateValidSessionWithAllRequiredFields() {
            Long userId = 1L;
            int timeoutMinutes = 30;
            String ipAddress = "192.168.1.1";
            String userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

            Session session = new Session(userId, timeoutMinutes, ipAddress, userAgent);

            assertThat(session.getId()).isNotNull().isNotBlank();
            assertThat(session.getUserId()).isEqualTo(userId);
            assertThat(session.getIpAddress()).isEqualTo(ipAddress);
            assertThat(session.getUserAgent()).isEqualTo(userAgent);
            assertThat(session.getIsActive()).isTrue();
            assertThat(session.getLastAccessedAt()).isNotNull();
            assertThat(session.getExpiresAt()).isNotNull();
            assertThat(session.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should generate unique session IDs")
        void shouldGenerateUniqueSessionIds() {
            Long userId = 1L;
            int timeoutMinutes = 30;
            String ipAddress = "192.168.1.1";
            String userAgent = "Mozilla/5.0";

            Session session1 = new Session(userId, timeoutMinutes, ipAddress, userAgent);
            Session session2 = new Session(userId, timeoutMinutes, ipAddress, userAgent);

            assertThat(session1.getId()).isNotEqualTo(session2.getId());
        }

        @Test
        @DisplayName("Should set expiration time correctly based on timeout")
        void shouldSetExpirationTimeCorrectlyBasedOnTimeout() {
            Long userId = 1L;
            int timeoutMinutes = 60;
            String ipAddress = "192.168.1.1";
            String userAgent = "Mozilla/5.0";

            LocalDateTime beforeCreation = LocalDateTime.now();
            Session session = new Session(userId, timeoutMinutes, ipAddress, userAgent);
            LocalDateTime afterCreation = LocalDateTime.now();

            LocalDateTime expectedMinExpiration = beforeCreation.plusMinutes(timeoutMinutes);
            LocalDateTime expectedMaxExpiration = afterCreation.plusMinutes(timeoutMinutes);

            assertThat(session.getExpiresAt())
                .isAfterOrEqualTo(expectedMinExpiration)
                .isBeforeOrEqualTo(expectedMaxExpiration);
        }

        @Test
        @DisplayName("Should create session with null optional fields")
        void shouldCreateSessionWithNullOptionalFields() {
            Long userId = 1L;
            int timeoutMinutes = 30;

            Session session = new Session(userId, timeoutMinutes, null, null);

            assertThat(session.getId()).isNotNull();
            assertThat(session.getUserId()).isEqualTo(userId);
            assertThat(session.getIpAddress()).isNull();
            assertThat(session.getUserAgent()).isNull();
            assertThat(session.getIsActive()).isTrue();
        }

        @Test
        @DisplayName("Should validate session creation with valid data")
        void shouldValidateSessionCreationWithValidData() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            Set<ConstraintViolation<Session>> violations = validator.validate(session);

            assertThat(violations).isEmpty();
        }
    }

    @Nested
    @DisplayName("Session Extension Tests")
    class SessionExtensionTests {

        @Test
        @DisplayName("Should extend session expiration time")
        void shouldExtendSessionExpirationTime() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            LocalDateTime originalExpiration = session.getExpiresAt();
            
            // Wait a small amount to ensure time difference
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            int extensionMinutes = 60;
            session.extendSession(extensionMinutes);

            assertThat(session.getExpiresAt()).isAfter(originalExpiration);
            assertThat(session.getLastAccessedAt()).isNotNull();
        }

        @Test
        @DisplayName("Should update last accessed time when extending session")
        void shouldUpdateLastAccessedTimeWhenExtendingSession() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            LocalDateTime originalLastAccessed = session.getLastAccessedAt();
            
            // Wait to ensure time difference
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            session.extendSession(30);

            assertThat(session.getLastAccessedAt()).isAfter(originalLastAccessed);
        }

        @Test
        @DisplayName("Should extend session with different timeout values")
        void shouldExtendSessionWithDifferentTimeoutValues() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");

            int[] extensionValues = {15, 30, 60, 120, 1440}; // 15 min to 24 hours

            for (int extension : extensionValues) {
                LocalDateTime beforeExtension = LocalDateTime.now();
                session.extendSession(extension);
                LocalDateTime afterExtension = LocalDateTime.now();

                LocalDateTime expectedMinExpiration = beforeExtension.plusMinutes(extension);
                LocalDateTime expectedMaxExpiration = afterExtension.plusMinutes(extension);

                assertThat(session.getExpiresAt())
                    .isAfterOrEqualTo(expectedMinExpiration)
                    .isBeforeOrEqualTo(expectedMaxExpiration);
            }
        }

        @Test
        @DisplayName("Should update last accessed time independently")
        void shouldUpdateLastAccessedTimeIndependently() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            LocalDateTime originalLastAccessed = session.getLastAccessedAt();
            LocalDateTime originalExpiration = session.getExpiresAt();
            
            // Wait to ensure time difference
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            session.updateLastAccessed();

            assertThat(session.getLastAccessedAt()).isAfter(originalLastAccessed);
            assertThat(session.getExpiresAt()).isEqualTo(originalExpiration); // Should not change
        }
    }

    @Nested
    @DisplayName("Session Expiration Tests")
    class SessionExpirationTests {

        @Test
        @DisplayName("Should detect expired session")
        void shouldDetectExpiredSession() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            
            // Manually set expiration to past time
            session.setExpiresAt(LocalDateTime.now().minusMinutes(1));

            assertThat(session.isExpired()).isTrue();
            assertThat(session.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should detect non-expired session")
        void shouldDetectNonExpiredSession() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");

            assertThat(session.isExpired()).isFalse();
            assertThat(session.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should calculate remaining minutes correctly")
        void shouldCalculateRemainingMinutesCorrectly() {
            Session session = new Session(1L, 60, "192.168.1.1", "Mozilla/5.0");

            long remainingMinutes = session.getRemainingMinutes();

            // Should be close to 60 minutes (allowing for small timing differences)
            assertThat(remainingMinutes).isBetween(59L, 60L);
        }

        @Test
        @DisplayName("Should return zero remaining minutes for expired session")
        void shouldReturnZeroRemainingMinutesForExpiredSession() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.setExpiresAt(LocalDateTime.now().minusMinutes(10));

            long remainingMinutes = session.getRemainingMinutes();

            assertThat(remainingMinutes).isEqualTo(0L);
        }

        @Test
        @DisplayName("Should handle session at exact expiration time")
        void shouldHandleSessionAtExactExpirationTime() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.setExpiresAt(LocalDateTime.now());

            // At exact expiration time, session should be considered expired
            assertThat(session.isExpired()).isTrue();
            assertThat(session.isValid()).isFalse();
            assertThat(session.getRemainingMinutes()).isEqualTo(0L);
        }
    }

    @Nested
    @DisplayName("Session Invalidation Tests")
    class SessionInvalidationTests {

        @Test
        @DisplayName("Should invalidate active session")
        void shouldInvalidateActiveSession() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            
            assertThat(session.getIsActive()).isTrue();
            assertThat(session.isValid()).isTrue();

            session.invalidate();

            assertThat(session.getIsActive()).isFalse();
            assertThat(session.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should handle multiple invalidation calls")
        void shouldHandleMultipleInvalidationCalls() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");

            session.invalidate();
            session.invalidate(); // Second call should not cause issues

            assertThat(session.getIsActive()).isFalse();
            assertThat(session.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should remain invalid even if not expired")
        void shouldRemainInvalidEvenIfNotExpired() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.invalidate();

            // Even though not expired, should be invalid due to inactive status
            assertThat(session.isExpired()).isFalse();
            assertThat(session.isValid()).isFalse();
        }
    }

    @Nested
    @DisplayName("Session Validation Edge Cases")
    class SessionValidationEdgeCases {

        @Test
        @DisplayName("Should validate session belongs to correct user")
        void shouldValidateSessionBelongsToCorrectUser() {
            Long userId = 1L;
            Session session = new Session(userId, 30, "192.168.1.1", "Mozilla/5.0");

            assertThat(session.belongsToUser(userId)).isTrue();
            assertThat(session.belongsToUser(2L)).isFalse();
            assertThat(session.belongsToUser(null)).isFalse();
        }

        @Test
        @DisplayName("Should handle null user ID in session")
        void shouldHandleNullUserIdInSession() {
            Session session = new Session();
            session.setUserId(null);

            assertThat(session.belongsToUser(1L)).isFalse();
            assertThat(session.belongsToUser(null)).isTrue();
        }

        @Test
        @DisplayName("Should validate required fields")
        void shouldValidateRequiredFields() {
            Session session = new Session();
            // Leave required fields null/empty
            session.setId("");
            session.setUserId(null);
            session.setExpiresAt(null);
            session.setLastAccessedAt(null);
            session.setIsActive(null);

            Set<ConstraintViolation<Session>> violations = validator.validate(session);

            assertThat(violations).isNotEmpty();
            
            // Check for specific field violations
            boolean hasIdViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("id"));
            boolean hasUserIdViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("userId"));
            boolean hasExpiresAtViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("expiresAt"));
            boolean hasLastAccessedViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("lastAccessedAt"));
            boolean hasIsActiveViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("isActive"));

            assertThat(hasIdViolation).isTrue();
            assertThat(hasUserIdViolation).isTrue();
            assertThat(hasExpiresAtViolation).isTrue();
            assertThat(hasLastAccessedViolation).isTrue();
            assertThat(hasIsActiveViolation).isTrue();
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "   ", "\t", "\n"})
        @DisplayName("Should reject blank session IDs")
        void shouldRejectBlankSessionIds(String blankId) {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.setId(blankId);

            Set<ConstraintViolation<Session>> violations = validator.validate(session);

            boolean hasIdViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("id"));

            assertThat(hasIdViolation).isTrue();
        }

        @Test
        @DisplayName("Should validate IP address length constraints")
        void shouldValidateIpAddressLengthConstraints() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            
            // Test maximum length (45 characters for IPv6)
            String maxLengthIp = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"; // 39 chars, valid
            session.setIpAddress(maxLengthIp);
            Set<ConstraintViolation<Session>> violations = validator.validate(session);
            
            boolean hasIpViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("ipAddress"));
            assertThat(hasIpViolation).isFalse();

            // Test exceeding maximum length
            String tooLongIp = "a".repeat(46);
            session.setIpAddress(tooLongIp);
            violations = validator.validate(session);
            
            hasIpViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("ipAddress"));
            assertThat(hasIpViolation).isTrue();
        }

        @Test
        @DisplayName("Should validate user agent length constraints")
        void shouldValidateUserAgentLengthConstraints() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            
            // Test maximum length (2000 characters)
            String maxLengthUserAgent = "a".repeat(2000);
            session.setUserAgent(maxLengthUserAgent);
            Set<ConstraintViolation<Session>> violations = validator.validate(session);
            
            boolean hasUserAgentViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("userAgent"));
            assertThat(hasUserAgentViolation).isFalse();

            // Test exceeding maximum length
            String tooLongUserAgent = "a".repeat(2001);
            session.setUserAgent(tooLongUserAgent);
            violations = validator.validate(session);
            
            hasUserAgentViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("userAgent"));
            assertThat(hasUserAgentViolation).isTrue();
        }

        @Test
        @DisplayName("Should handle expiration time in past during validation")
        void shouldHandleExpirationTimeInPastDuringValidation() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.setExpiresAt(LocalDateTime.now().minusHours(1));

            Set<ConstraintViolation<Session>> violations = validator.validate(session);

            // The @Future annotation should catch past expiration times
            boolean hasExpirationViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("expiresAt"));
            assertThat(hasExpirationViolation).isTrue();
        }
    }

    @Nested
    @DisplayName("Session Cleanup and Lifecycle Callbacks")
    class SessionCleanupAndLifecycleTests {

        @Test
        @DisplayName("Should auto-generate ID on persist if missing")
        void shouldAutoGenerateIdOnPersistIfMissing() {
            Session session = new Session();
            session.setUserId(1L);
            session.setExpiresAt(LocalDateTime.now().plusMinutes(30));
            session.setId(null); // Explicitly set to null

            // Simulate @PrePersist callback
            session.onCreate();

            assertThat(session.getId()).isNotNull().isNotBlank();
        }

        @Test
        @DisplayName("Should set default values on persist")
        void shouldSetDefaultValuesOnPersist() {
            Session session = new Session();
            session.setUserId(1L);
            session.setExpiresAt(LocalDateTime.now().plusMinutes(30));
            session.setLastAccessedAt(null);
            session.setIsActive(null);

            // Simulate @PrePersist callback
            session.onCreate();

            assertThat(session.getLastAccessedAt()).isNotNull();
            assertThat(session.getIsActive()).isTrue();
        }

        @Test
        @DisplayName("Should not overwrite existing ID on persist")
        void shouldNotOverwriteExistingIdOnPersist() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            String originalId = session.getId();

            // Simulate @PrePersist callback
            session.onCreate();

            assertThat(session.getId()).isEqualTo(originalId);
        }

        @Test
        @DisplayName("Should auto-deactivate expired session on update")
        void shouldAutoDeactivateExpiredSessionOnUpdate() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.setExpiresAt(LocalDateTime.now().minusMinutes(10)); // Set to expired
            session.setIsActive(true); // Explicitly set as active

            // Simulate @PreUpdate callback
            session.onUpdate();

            assertThat(session.getIsActive()).isFalse();
        }

        @Test
        @DisplayName("Should not change active status for non-expired session on update")
        void shouldNotChangeActiveStatusForNonExpiredSessionOnUpdate() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.setIsActive(true);

            // Simulate @PreUpdate callback
            session.onUpdate();

            assertThat(session.getIsActive()).isTrue();
        }

        @Test
        @DisplayName("Should maintain inactive status for expired session on update")
        void shouldMaintainInactiveStatusForExpiredSessionOnUpdate() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            session.setExpiresAt(LocalDateTime.now().minusMinutes(10));
            session.setIsActive(false); // Already inactive

            // Simulate @PreUpdate callback
            session.onUpdate();

            assertThat(session.getIsActive()).isFalse();
        }
    }

    @Nested
    @DisplayName("Session Equality and Hash Code Tests")
    class SessionEqualityTests {

        @Test
        @DisplayName("Should be equal when IDs are the same")
        void shouldBeEqualWhenIdsAreTheSame() {
            Session session1 = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            Session session2 = new Session(2L, 60, "10.0.0.1", "Chrome");
            session2.setId(session1.getId()); // Same ID

            assertThat(session1).isEqualTo(session2);
            assertThat(session1.hashCode()).isEqualTo(session2.hashCode());
        }

        @Test
        @DisplayName("Should not be equal when IDs are different")
        void shouldNotBeEqualWhenIdsAreDifferent() {
            Session session1 = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            Session session2 = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");

            // Different sessions should have different IDs
            assertThat(session1).isNotEqualTo(session2);
        }

        @Test
        @DisplayName("Should handle null comparisons correctly")
        void shouldHandleNullComparisonsCorrectly() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");

            assertThat(session).isNotEqualTo(null);
            assertThat(session.equals(null)).isFalse();
        }

        @Test
        @DisplayName("Should handle different class comparisons correctly")
        void shouldHandleDifferentClassComparisonsCorrectly() {
            Session session = new Session(1L, 30, "192.168.1.1", "Mozilla/5.0");
            String notASession = "not a session";

            assertThat(session).isNotEqualTo(notASession);
        }
    }
}