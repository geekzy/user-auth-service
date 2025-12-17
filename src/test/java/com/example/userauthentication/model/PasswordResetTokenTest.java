package com.example.userauthentication.model;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for PasswordResetToken entity.
 * Tests token generation, expiration, single-use enforcement, and validation scenarios.
 * 
 * Requirements: 4.5 - Reset token single-use enforcement
 */
class PasswordResetTokenTest {

    private Long testUserId;
    private int defaultExpirationMinutes;

    @BeforeEach
    void setUp() {
        testUserId = 123L;
        defaultExpirationMinutes = 60; // 1 hour
    }

    @Nested
    class TokenGenerationTests {

        @Test
        void testTokenCreationWithValidParameters() {
            // Test creating a token with valid parameters
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertNotNull(token.getToken(), "Token should not be null");
            assertFalse(token.getToken().isEmpty(), "Token should not be empty");
            assertEquals(testUserId, token.getUserId(), "User ID should match");
            assertFalse(token.getUsed(), "Token should not be marked as used initially");
            assertNull(token.getUsedAt(), "Used timestamp should be null initially");
            assertNotNull(token.getExpiresAt(), "Expiration time should be set");
            assertTrue(token.getExpiresAt().isAfter(LocalDateTime.now()), 
                      "Expiration time should be in the future");
        }

        @Test
        void testTokenUniqueness() {
            // Test that multiple tokens are unique
            Set<String> tokens = new HashSet<>();
            int tokenCount = 100;
            
            for (int i = 0; i < tokenCount; i++) {
                PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
                String tokenValue = token.getToken();
                
                assertFalse(tokens.contains(tokenValue), 
                           "Token should be unique: " + tokenValue);
                tokens.add(tokenValue);
            }
            
            assertEquals(tokenCount, tokens.size(), "All tokens should be unique");
        }

        @Test
        void testTokenLength() {
            // Test that generated tokens have appropriate length
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            String tokenValue = token.getToken();
            
            assertTrue(tokenValue.length() >= 32, 
                      "Token should be at least 32 characters long");
            assertTrue(tokenValue.length() <= 255, 
                      "Token should not exceed 255 characters");
        }

        @Test
        void testTokenFormat() {
            // Test that token contains only valid characters
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            String tokenValue = token.getToken();
            
            // Should contain only URL-safe Base64 characters and digits
            assertTrue(tokenValue.matches("[A-Za-z0-9_-]+"), 
                      "Token should contain only URL-safe characters");
        }

        @Test
        void testExpirationTimeCalculation() {
            // Test that expiration time is calculated correctly
            int expirationMinutes = 30;
            LocalDateTime beforeCreation = LocalDateTime.now();
            
            PasswordResetToken token = new PasswordResetToken(testUserId, expirationMinutes);
            
            LocalDateTime afterCreation = LocalDateTime.now();
            LocalDateTime expectedExpiration = beforeCreation.plusMinutes(expirationMinutes);
            LocalDateTime actualExpiration = token.getExpiresAt();
            
            assertTrue(actualExpiration.isAfter(expectedExpiration.minusSeconds(1)), 
                      "Expiration should be approximately correct");
            assertTrue(actualExpiration.isBefore(afterCreation.plusMinutes(expirationMinutes).plusSeconds(1)), 
                      "Expiration should be approximately correct");
        }
    }

    @Nested
    class TokenValidationTests {

        @Test
        void testValidTokenValidation() {
            // Test validation of a valid token
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertTrue(token.isValid(), "Fresh token should be valid");
            assertFalse(token.isExpired(), "Fresh token should not be expired");
            assertFalse(token.isUsed(), "Fresh token should not be used");
        }

        @Test
        void testExpiredTokenValidation() {
            // Test validation of an expired token
            PasswordResetToken token = new PasswordResetToken(testUserId, -1); // Expired 1 minute ago
            
            assertFalse(token.isValid(), "Expired token should not be valid");
            assertTrue(token.isExpired(), "Token should be marked as expired");
            assertFalse(token.isUsed(), "Expired token should not be marked as used");
        }

        @Test
        void testUsedTokenValidation() {
            // Test validation of a used token
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            token.markAsUsed();
            
            assertFalse(token.isValid(), "Used token should not be valid");
            assertFalse(token.isExpired(), "Used token should not be expired (still within time)");
            assertTrue(token.isUsed(), "Token should be marked as used");
            assertNotNull(token.getUsedAt(), "Used timestamp should be set");
        }

        @Test
        void testUserOwnershipValidation() {
            // Test validation of token ownership
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertTrue(token.belongsToUser(testUserId), "Token should belong to correct user");
            assertFalse(token.belongsToUser(456L), "Token should not belong to different user");
            assertFalse(token.belongsToUser(null), "Token should not belong to null user");
        }

        @Test
        void testPasswordResetUsageValidation() {
            // Test comprehensive validation for password reset usage
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertTrue(token.canBeUsedForPasswordReset(testUserId), 
                      "Valid token should be usable for password reset");
            assertFalse(token.canBeUsedForPasswordReset(456L), 
                       "Token should not be usable by different user");
        }

        @Test
        void testPasswordResetUsageAfterExpiration() {
            // Test password reset usage validation for expired token
            PasswordResetToken token = new PasswordResetToken(testUserId, -1); // Expired
            
            assertFalse(token.canBeUsedForPasswordReset(testUserId), 
                       "Expired token should not be usable for password reset");
        }

        @Test
        void testPasswordResetUsageAfterUse() {
            // Test password reset usage validation for used token
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            token.markAsUsed();
            
            assertFalse(token.canBeUsedForPasswordReset(testUserId), 
                       "Used token should not be usable for password reset");
        }
    }

    @Nested
    class SingleUseEnforcementTests {

        @Test
        void testMarkAsUsedFunctionality() {
            // Test marking token as used
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertFalse(token.isUsed(), "Token should not be used initially");
            assertNull(token.getUsedAt(), "Used timestamp should be null initially");
            
            LocalDateTime beforeUsage = LocalDateTime.now();
            token.markAsUsed();
            LocalDateTime afterUsage = LocalDateTime.now();
            
            assertTrue(token.isUsed(), "Token should be marked as used");
            assertNotNull(token.getUsedAt(), "Used timestamp should be set");
            assertTrue(token.getUsedAt().isAfter(beforeUsage.minusSeconds(1)), 
                      "Used timestamp should be recent");
            assertTrue(token.getUsedAt().isBefore(afterUsage.plusSeconds(1)), 
                      "Used timestamp should be recent");
        }

        @Test
        void testSingleUseEnforcement() {
            // Test that token can only be used once
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            // First usage
            assertTrue(token.canBeUsedForPasswordReset(testUserId), 
                      "Token should be usable initially");
            token.markAsUsed();
            
            // Second usage attempt
            assertFalse(token.canBeUsedForPasswordReset(testUserId), 
                       "Token should not be usable after being used");
            assertFalse(token.isValid(), "Used token should not be valid");
        }

        @Test
        void testMultipleMarkAsUsedCalls() {
            // Test multiple calls to markAsUsed
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            token.markAsUsed();
            LocalDateTime firstUsedAt = token.getUsedAt();
            
            // Wait a moment and mark as used again
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            token.markAsUsed();
            LocalDateTime secondUsedAt = token.getUsedAt();
            
            // Should still be marked as used, but timestamp might be updated
            assertTrue(token.isUsed(), "Token should remain marked as used");
            assertNotNull(secondUsedAt, "Used timestamp should still be set");
        }
    }

    @Nested
    class ExpirationTests {

        @Test
        void testRemainingMinutesCalculation() {
            // Test calculation of remaining minutes
            int expirationMinutes = 120; // 2 hours
            PasswordResetToken token = new PasswordResetToken(testUserId, expirationMinutes);
            
            long remainingMinutes = token.getRemainingMinutes();
            
            assertTrue(remainingMinutes > 0, "Should have remaining minutes");
            assertTrue(remainingMinutes <= expirationMinutes, 
                      "Remaining minutes should not exceed expiration time");
            assertTrue(remainingMinutes >= expirationMinutes - 1, 
                      "Remaining minutes should be close to expiration time");
        }

        @Test
        void testRemainingMinutesForExpiredToken() {
            // Test remaining minutes for expired token
            PasswordResetToken token = new PasswordResetToken(testUserId, -60); // Expired 1 hour ago
            
            long remainingMinutes = token.getRemainingMinutes();
            assertEquals(0, remainingMinutes, "Expired token should have 0 remaining minutes");
        }

        @Test
        void testExpirationBoundary() {
            // Test expiration at the exact boundary
            PasswordResetToken token = new PasswordResetToken(testUserId, 0); // Expires now
            
            // Token might be expired or about to expire
            // This tests the boundary condition
            long remainingMinutes = token.getRemainingMinutes();
            assertTrue(remainingMinutes <= 1, "Token at expiration boundary should have <= 1 minute");
        }
    }

    @Nested
    class EntityLifecycleTests {

        @Test
        void testPrePersistCallback() {
            // Test @PrePersist callback functionality
            PasswordResetToken token = new PasswordResetToken();
            token.setUserId(testUserId);
            token.setExpiresAt(LocalDateTime.now().plusMinutes(60));
            
            // Simulate @PrePersist call
            token.onCreate();
            
            assertNotNull(token.getToken(), "Token should be generated in @PrePersist");
            assertFalse(token.getUsed(), "Used should be set to false in @PrePersist");
        }

        @Test
        void testPreUpdateCallback() {
            // Test @PreUpdate callback functionality
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            token.setUsed(true);
            token.setUsedAt(null); // Simulate used being set without usedAt
            
            // Simulate @PreUpdate call
            token.onUpdate();
            
            assertNotNull(token.getUsedAt(), "UsedAt should be set in @PreUpdate when used is true");
        }

        @Test
        void testPreUpdateCallbackWhenNotUsed() {
            // Test @PreUpdate callback when token is not used
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            LocalDateTime originalUsedAt = token.getUsedAt();
            
            // Simulate @PreUpdate call
            token.onUpdate();
            
            assertEquals(originalUsedAt, token.getUsedAt(), 
                        "UsedAt should not be modified when token is not used");
        }
    }

    @Nested
    class EqualityAndHashCodeTests {

        @Test
        void testEquality() {
            // Test equality based on token value
            PasswordResetToken token1 = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            PasswordResetToken token2 = new PasswordResetToken();
            token2.setToken(token1.getToken());
            token2.setUserId(456L); // Different user ID
            
            assertEquals(token1, token2, "Tokens with same token value should be equal");
            assertEquals(token1.hashCode(), token2.hashCode(), "Hash codes should be equal");
        }

        @Test
        void testInequality() {
            // Test inequality with different token values
            PasswordResetToken token1 = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            PasswordResetToken token2 = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertNotEquals(token1, token2, "Tokens with different token values should not be equal");
        }

        @Test
        void testEqualityWithNull() {
            // Test equality with null
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertNotEquals(token, null, "Token should not equal null");
        }

        @Test
        void testEqualityWithDifferentClass() {
            // Test equality with different class
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            String otherObject = "not a token";
            
            assertNotEquals(token, otherObject, "Token should not equal different class");
        }

        @Test
        void testSelfEquality() {
            // Test self equality
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            
            assertEquals(token, token, "Token should equal itself");
        }
    }

    @Nested
    class EdgeCaseTests {

        @Test
        void testNullUserIdHandling() {
            // Test handling of null user ID
            PasswordResetToken token = new PasswordResetToken();
            token.setUserId(null);
            token.setToken("test-token");
            token.setExpiresAt(LocalDateTime.now().plusMinutes(60));
            token.setUsed(false);
            
            assertFalse(token.belongsToUser(testUserId), "Token should not belong to any user when userId is null");
            assertTrue(token.belongsToUser(null), "Token with null userId should belong to null user (Objects.equals behavior)");
            assertFalse(token.canBeUsedForPasswordReset(testUserId), "Token with null userId should not be usable");
        }

        @Test
        void testEmptyTokenHandling() {
            // Test handling of empty token
            PasswordResetToken token = new PasswordResetToken();
            token.setToken("");
            token.setUserId(testUserId);
            token.setExpiresAt(LocalDateTime.now().plusMinutes(60));
            token.setUsed(false);
            
            // Simulate @PrePersist to generate token if empty
            token.onCreate();
            
            assertNotNull(token.getToken(), "Empty token should be regenerated");
            assertFalse(token.getToken().isEmpty(), "Token should not be empty after onCreate");
        }

        @Test
        void testNullTokenHandling() {
            // Test handling of null token
            PasswordResetToken token = new PasswordResetToken();
            token.setToken(null);
            token.setUserId(testUserId);
            token.setExpiresAt(LocalDateTime.now().plusMinutes(60));
            token.setUsed(false);
            
            // Simulate @PrePersist to generate token if null
            token.onCreate();
            
            assertNotNull(token.getToken(), "Null token should be generated");
            assertFalse(token.getToken().isEmpty(), "Generated token should not be empty");
        }

        @Test
        void testVeryShortExpirationTime() {
            // Test with very short expiration time
            PasswordResetToken token = new PasswordResetToken(testUserId, 0); // Expires immediately
            
            // Token might be expired immediately or very soon
            assertTrue(token.getRemainingMinutes() <= 1, "Very short expiration should have <= 1 minute remaining");
        }

        @Test
        void testNegativeExpirationTime() {
            // Test with negative expiration time (already expired)
            PasswordResetToken token = new PasswordResetToken(testUserId, -30); // Expired 30 minutes ago
            
            assertTrue(token.isExpired(), "Token with negative expiration should be expired");
            assertFalse(token.isValid(), "Expired token should not be valid");
            assertEquals(0, token.getRemainingMinutes(), "Expired token should have 0 remaining minutes");
        }

        @Test
        void testToStringMethod() {
            // Test toString method doesn't expose full token
            PasswordResetToken token = new PasswordResetToken(testUserId, defaultExpirationMinutes);
            String tokenString = token.toString();
            
            assertNotNull(tokenString, "toString should not return null");
            assertTrue(tokenString.contains("PasswordResetToken"), "toString should contain class name");
            assertTrue(tokenString.contains("userId=" + testUserId), "toString should contain user ID");
            
            // Should not contain the full token for security
            String fullToken = token.getToken();
            if (fullToken.length() > 8) {
                assertFalse(tokenString.contains(fullToken), "toString should not expose full token");
            }
        }
    }
}