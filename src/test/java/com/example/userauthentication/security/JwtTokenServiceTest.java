package com.example.userauthentication.security;

import com.example.userauthentication.config.SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for JWT token generation and validation functionality.
 * Tests JWT token generation, validation, uniqueness, and security properties.
 * 
 * Requirements: 5.3 - JWT token security
 */
class JwtTokenServiceTest {

    private JwtTokenService jwtTokenService;
    private SecurityProperties securityProperties;

    @BeforeEach
    void setUp() {
        // Set up security properties
        securityProperties = new SecurityProperties();
        
        SecurityProperties.Jwt jwt = new SecurityProperties.Jwt();
        // Generate a 64-byte (512-bit) secret key for HS512
        jwt.setSecret("mySecretKey123456789012345678901234567890123456789012345678901234567890"); // 64+ chars for HS512
        jwt.setExpiration(86400000L); // 24 hours in milliseconds
        securityProperties.setJwt(jwt);
        
        jwtTokenService = new JwtTokenService(securityProperties);
    }

    @Nested
    class TokenGenerationTests {

        @Test
        void testGenerateTokenProducesValidToken() {
            // Test that token generation produces a non-null, non-empty token
            Long userId = 1L;
            String email = "test@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            
            assertNotNull(token, "Generated token should not be null");
            assertFalse(token.trim().isEmpty(), "Generated token should not be empty");
            assertTrue(token.contains("."), "JWT token should contain dots as separators");
        }

        @Test
        void testGenerateTokenWithValidUserData() {
            // Test token generation with various valid user data
            Long userId = 123L;
            String email = "user@domain.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(token);
            
            assertNotNull(tokenInfo, "Token validation should succeed");
            assertEquals(userId, tokenInfo.getUserId(), "User ID should match");
            assertEquals(email, tokenInfo.getEmail(), "Email should match");
            assertEquals("access", tokenInfo.getType(), "Token type should be 'access'");
        }

        @Test
        void testGenerateRefreshToken() {
            // Test refresh token generation
            Long userId = 456L;
            String email = "refresh@example.com";
            
            String refreshToken = jwtTokenService.generateRefreshToken(userId, email);
            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(refreshToken);
            
            assertNotNull(tokenInfo, "Refresh token validation should succeed");
            assertEquals(userId, tokenInfo.getUserId(), "User ID should match");
            assertEquals(email, tokenInfo.getEmail(), "Email should match");
            assertEquals("refresh", tokenInfo.getType(), "Token type should be 'refresh'");
        }

        @Test
        void testTokenExpirationTime() {
            // Test that token has proper expiration time
            Long userId = 789L;
            String email = "expiry@example.com";
            
            LocalDateTime beforeGeneration = LocalDateTime.now();
            String token = jwtTokenService.generateToken(userId, email);
            LocalDateTime afterGeneration = LocalDateTime.now();
            
            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(token);
            assertNotNull(tokenInfo, "Token should be valid");
            
            // Token should expire approximately 24 hours from now
            LocalDateTime expectedExpiry = beforeGeneration.plusHours(24);
            LocalDateTime actualExpiry = tokenInfo.getExpiresAt();
            
            assertTrue(actualExpiry.isAfter(expectedExpiry.minusMinutes(1)), 
                      "Token expiry should be around 24 hours from generation");
            assertTrue(actualExpiry.isBefore(afterGeneration.plusHours(24).plusMinutes(1)), 
                      "Token expiry should not be too far in the future");
        }

        @Test
        void testRefreshTokenLongerExpiration() {
            // Test that refresh token has longer expiration than access token
            Long userId = 999L;
            String email = "longerexpiry@example.com";
            
            String accessToken = jwtTokenService.generateToken(userId, email);
            String refreshToken = jwtTokenService.generateRefreshToken(userId, email);
            
            JwtTokenService.JwtTokenInfo accessInfo = jwtTokenService.validateToken(accessToken);
            JwtTokenService.JwtTokenInfo refreshInfo = jwtTokenService.validateToken(refreshToken);
            
            assertNotNull(accessInfo, "Access token should be valid");
            assertNotNull(refreshInfo, "Refresh token should be valid");
            
            assertTrue(refreshInfo.getExpiresAt().isAfter(accessInfo.getExpiresAt()), 
                      "Refresh token should expire later than access token");
        }
    }

    @Nested
    class TokenUniquenessTests {

        @Test
        void testTokenUniquenessForSameUser() throws InterruptedException {
            // Test that same user generates different tokens each time
            Long userId = 100L;
            String email = "unique@example.com";
            
            String token1 = jwtTokenService.generateToken(userId, email);
            Thread.sleep(1000); // Wait 1 second to ensure different timestamp
            String token2 = jwtTokenService.generateToken(userId, email);
            
            assertNotEquals(token1, token2, 
                           "Same user should generate different tokens due to timestamp");
        }

        @Test
        void testTokenUniquenessAcrossUsers() {
            // Test that different users generate different tokens
            String token1 = jwtTokenService.generateToken(1L, "user1@example.com");
            String token2 = jwtTokenService.generateToken(2L, "user2@example.com");
            
            assertNotEquals(token1, token2, 
                           "Different users should generate different tokens");
        }

        @Test
        void testMultipleTokenUniqueness() throws InterruptedException {
            // Test uniqueness across multiple token generations
            Long userId = 200L;
            String email = "multiple@example.com";
            Set<String> tokens = new HashSet<>();
            int iterations = 5; // Reduced iterations to make test faster
            
            for (int i = 0; i < iterations; i++) {
                String token = jwtTokenService.generateToken(userId, email);
                assertFalse(tokens.contains(token), 
                           "Token should be unique across multiple generations");
                tokens.add(token);
                
                // Wait 1 second to ensure different timestamps
                Thread.sleep(1000);
            }
            
            assertEquals(iterations, tokens.size(), "All tokens should be unique");
        }
    }

    @Nested
    class TokenValidationTests {

        @Test
        void testValidTokenValidation() {
            // Test validation of valid token
            Long userId = 300L;
            String email = "valid@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(token);
            
            assertNotNull(tokenInfo, "Valid token should pass validation");
            assertEquals(userId, tokenInfo.getUserId(), "User ID should be extracted correctly");
            assertEquals(email, tokenInfo.getEmail(), "Email should be extracted correctly");
            assertFalse(tokenInfo.isExpired(), "Fresh token should not be expired");
        }

        @Test
        void testInvalidTokenValidation() {
            // Test validation of invalid/malformed tokens
            String[] invalidTokens = {
                "invalid.token.here",
                "not.a.jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature",
                "",
                null
            };
            
            for (String invalidToken : invalidTokens) {
                JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(invalidToken);
                assertNull(tokenInfo, "Invalid token should fail validation: " + invalidToken);
            }
        }

        @Test
        void testTamperedTokenValidation() {
            // Test validation of tampered token
            Long userId = 400L;
            String email = "tampered@example.com";
            
            String validToken = jwtTokenService.generateToken(userId, email);
            
            // Tamper with the token by changing a character
            String tamperedToken = validToken.substring(0, validToken.length() - 5) + "XXXXX";
            
            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(tamperedToken);
            assertNull(tokenInfo, "Tampered token should fail validation");
        }
    }

    @Nested
    class TokenBlacklistTests {

        @Test
        void testTokenBlacklisting() {
            // Test token blacklisting functionality
            Long userId = 500L;
            String email = "blacklist@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            
            // Token should be valid before blacklisting
            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(token);
            assertNotNull(tokenInfo, "Token should be valid before blacklisting");
            
            // Blacklist the token
            jwtTokenService.blacklistToken(token);
            
            // Token should be invalid after blacklisting
            tokenInfo = jwtTokenService.validateToken(token);
            assertNull(tokenInfo, "Token should be invalid after blacklisting");
            
            // Check blacklist status
            assertTrue(jwtTokenService.isTokenBlacklisted(token), 
                      "Token should be marked as blacklisted");
        }

        @Test
        void testBlacklistNullToken() {
            // Test blacklisting null or empty tokens
            jwtTokenService.blacklistToken(null);
            jwtTokenService.blacklistToken("");
            jwtTokenService.blacklistToken("   ");
            
            // Should not throw exceptions
            assertFalse(jwtTokenService.isTokenBlacklisted(null), 
                       "Null token should not be considered blacklisted");
            assertFalse(jwtTokenService.isTokenBlacklisted(""), 
                       "Empty token should not be considered blacklisted");
        }
    }

    @Nested
    class TokenRefreshTests {

        @Test
        void testRefreshAccessToken() {
            // Test refreshing access token using refresh token
            Long userId = 600L;
            String email = "refresh@example.com";
            
            String refreshToken = jwtTokenService.generateRefreshToken(userId, email);
            String newAccessToken = jwtTokenService.refreshAccessToken(refreshToken);
            
            assertNotNull(newAccessToken, "New access token should be generated");
            
            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(newAccessToken);
            assertNotNull(tokenInfo, "New access token should be valid");
            assertEquals(userId, tokenInfo.getUserId(), "User ID should match");
            assertEquals(email, tokenInfo.getEmail(), "Email should match");
            assertEquals("access", tokenInfo.getType(), "New token should be access type");
        }

        @Test
        void testRefreshWithAccessToken() {
            // Test that access token cannot be used to refresh
            Long userId = 700L;
            String email = "noaccess@example.com";
            
            String accessToken = jwtTokenService.generateToken(userId, email);
            String newToken = jwtTokenService.refreshAccessToken(accessToken);
            
            assertNull(newToken, "Access token should not be able to refresh");
        }

        @Test
        void testRefreshWithInvalidToken() {
            // Test refresh with invalid token
            String invalidToken = "invalid.refresh.token";
            String newToken = jwtTokenService.refreshAccessToken(invalidToken);
            
            assertNull(newToken, "Invalid token should not be able to refresh");
        }
    }

    @Nested
    class TokenUtilityTests {

        @Test
        void testExtractUserIdFromToken() {
            // Test extracting user ID from token
            Long userId = 800L;
            String email = "extract@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            Long extractedUserId = jwtTokenService.extractUserIdFromToken(token);
            
            assertEquals(userId, extractedUserId, "Extracted user ID should match");
        }

        @Test
        void testExtractUserIdFromInvalidToken() {
            // Test extracting user ID from invalid token
            String invalidToken = "invalid.token.here";
            Long extractedUserId = jwtTokenService.extractUserIdFromToken(invalidToken);
            
            assertNull(extractedUserId, "Should not extract user ID from invalid token");
        }

        @Test
        void testGetTokenExpiration() {
            // Test getting token expiration
            Long userId = 900L;
            String email = "expiration@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            LocalDateTime expiration = jwtTokenService.getTokenExpiration(token);
            
            assertNotNull(expiration, "Should extract expiration from valid token");
            assertTrue(expiration.isAfter(LocalDateTime.now()), 
                      "Expiration should be in the future");
        }

        @Test
        void testIsTokenNearExpiry() {
            // Test checking if token is near expiry
            Long userId = 1000L;
            String email = "nearexpiry@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            boolean isNearExpiry = jwtTokenService.isTokenNearExpiry(token);
            
            assertFalse(isNearExpiry, "Fresh token should not be near expiry");
        }

        @Test
        void testIsInvalidTokenNearExpiry() {
            // Test that invalid token is considered near expiry
            String invalidToken = "invalid.token.here";
            boolean isNearExpiry = jwtTokenService.isTokenNearExpiry(invalidToken);
            
            assertTrue(isNearExpiry, "Invalid token should be considered near expiry");
        }
    }

    @Nested
    class TokenSecurityTests {

        @Test
        void testTokenContainsNoSensitiveData() {
            // Test that token doesn't contain sensitive data in plain text
            Long userId = 1100L;
            String email = "security@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            
            // Token should not contain email in plain text (it's in payload but encoded)
            assertFalse(token.contains(email), 
                       "Token should not contain email in plain text");
            assertFalse(token.contains(userId.toString()), 
                       "Token should not contain user ID in plain text");
        }

        @Test
        void testTokenFormat() {
            // Test that token follows JWT format (header.payload.signature)
            Long userId = 1200L;
            String email = "format@example.com";
            
            String token = jwtTokenService.generateToken(userId, email);
            String[] parts = token.split("\\.");
            
            assertEquals(3, parts.length, "JWT should have 3 parts separated by dots");
            
            for (String part : parts) {
                assertFalse(part.isEmpty(), "JWT parts should not be empty");
            }
        }

        @Test
        void testTokenSignatureValidation() {
            // Test that tokens with different secrets fail validation
            SecurityProperties differentProps = new SecurityProperties();
            SecurityProperties.Jwt jwt = new SecurityProperties.Jwt();
            jwt.setSecret("differentSecretKey123456789012345678901234567890123456789012345678901234567890");
            jwt.setExpiration(86400000L);
            differentProps.setJwt(jwt);
            
            JwtTokenService differentService = new JwtTokenService(differentProps);
            
            Long userId = 1300L;
            String email = "signature@example.com";
            
            // Generate token with original service
            String token = jwtTokenService.generateToken(userId, email);
            
            // Try to validate with different service (different secret)
            JwtTokenService.JwtTokenInfo tokenInfo = differentService.validateToken(token);
            assertNull(tokenInfo, "Token should fail validation with different secret");
        }
    }
}