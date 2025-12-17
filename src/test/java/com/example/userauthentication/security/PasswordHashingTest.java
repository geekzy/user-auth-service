package com.example.userauthentication.security;

import com.example.userauthentication.config.SecurityConfig;
import com.example.userauthentication.config.SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for password hashing functionality using BCrypt.
 * Tests BCrypt password encoding, verification, uniqueness, and security properties.
 * 
 * Requirements: 5.1 - Password hashing security
 */
class PasswordHashingTest {

    private PasswordEncoder passwordEncoder;
    private SecurityProperties securityProperties;

    @BeforeEach
    void setUp() {
        // Set up security properties with BCrypt rounds
        securityProperties = new SecurityProperties();
        SecurityProperties.Password password = new SecurityProperties.Password();
        SecurityProperties.Password.Bcrypt bcrypt = new SecurityProperties.Password.Bcrypt();
        bcrypt.setRounds(12); // Use same rounds as production config
        password.setBcrypt(bcrypt);
        securityProperties.setPassword(password);
        
        // Create SecurityConfig and get password encoder
        SecurityConfig securityConfig = new SecurityConfig(securityProperties, null, null);
        passwordEncoder = securityConfig.passwordEncoder();
    }

    @Test
    void testPasswordEncodingProducesHash() {
        // Test that password encoding produces a non-null hash
        String password = "testPassword123!";
        String hash = passwordEncoder.encode(password);
        
        assertNotNull(hash, "Password hash should not be null");
        assertNotEquals(password, hash, "Hash should not equal original password");
        assertTrue(hash.length() > 0, "Hash should not be empty");
    }

    @Test
    void testPasswordVerificationWithCorrectPassword() {
        // Test that correct password verification returns true
        String password = "correctPassword123!";
        String hash = passwordEncoder.encode(password);
        
        assertTrue(passwordEncoder.matches(password, hash), 
                  "Password verification should return true for correct password");
    }

    @Test
    void testPasswordVerificationWithIncorrectPassword() {
        // Test that incorrect password verification returns false
        String correctPassword = "correctPassword123!";
        String incorrectPassword = "wrongPassword456!";
        String hash = passwordEncoder.encode(correctPassword);
        
        assertFalse(passwordEncoder.matches(incorrectPassword, hash), 
                   "Password verification should return false for incorrect password");
    }

    @Test
    void testPasswordHashUniqueness() {
        // Test that same password produces different hashes (due to salt)
        String password = "samePassword123!";
        String hash1 = passwordEncoder.encode(password);
        String hash2 = passwordEncoder.encode(password);
        
        assertNotEquals(hash1, hash2, 
                       "Same password should produce different hashes due to salt");
        
        // Both hashes should still verify the original password
        assertTrue(passwordEncoder.matches(password, hash1), 
                  "First hash should verify original password");
        assertTrue(passwordEncoder.matches(password, hash2), 
                  "Second hash should verify original password");
    }

    @Test
    void testMultiplePasswordHashUniqueness() {
        // Test uniqueness across multiple password encodings
        String password = "uniquenessTest123!";
        Set<String> hashes = new HashSet<>();
        int iterations = 10;
        
        for (int i = 0; i < iterations; i++) {
            String hash = passwordEncoder.encode(password);
            assertFalse(hashes.contains(hash), 
                       "Hash should be unique across multiple encodings");
            hashes.add(hash);
        }
        
        assertEquals(iterations, hashes.size(), 
                    "All hashes should be unique");
    }

    @Test
    void testPasswordHashFormat() {
        // Test that BCrypt hash follows expected format
        String password = "formatTest123!";
        String hash = passwordEncoder.encode(password);
        
        // BCrypt hash should start with $2a$, $2b$, or $2y$ followed by rounds
        assertTrue(hash.matches("^\\$2[aby]\\$\\d{2}\\$.+"), 
                  "Hash should follow BCrypt format");
        
        // Should contain the configured number of rounds
        assertTrue(hash.contains("$12$"), 
                  "Hash should contain configured BCrypt rounds (12)");
    }

    @Test
    void testPasswordHashLength() {
        // Test that BCrypt hash has expected length
        String password = "lengthTest123!";
        String hash = passwordEncoder.encode(password);
        
        // BCrypt hash should be 60 characters long
        assertEquals(60, hash.length(), 
                    "BCrypt hash should be 60 characters long");
    }

    @Test
    void testEmptyPasswordHandling() {
        // Test handling of empty password
        String emptyPassword = "";
        String hash = passwordEncoder.encode(emptyPassword);
        
        assertNotNull(hash, "Hash should not be null even for empty password");
        assertTrue(passwordEncoder.matches(emptyPassword, hash), 
                  "Empty password should verify against its hash");
    }

    @Test
    void testNullPasswordHandling() {
        // Test handling of null password - should throw exception
        assertThrows(IllegalArgumentException.class, () -> {
            passwordEncoder.encode(null);
        }, "Encoding null password should throw IllegalArgumentException");
    }

    @Test
    void testSpecialCharacterPasswords() {
        // Test passwords with special characters
        String[] specialPasswords = {
            "password!@#$%^&*()",
            "пароль123", // Cyrillic characters
            "密码123", // Chinese characters
            "password\n\t\r", // Whitespace characters
            "password\"'`", // Quote characters
        };
        
        for (String password : specialPasswords) {
            String hash = passwordEncoder.encode(password);
            assertTrue(passwordEncoder.matches(password, hash), 
                      "Special character password should verify correctly: " + password);
        }
    }

    @Test
    void testLongPasswordHandling() {
        // Test very long password (BCrypt has 72 byte limit)
        StringBuilder longPassword = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            longPassword.append("a");
        }
        String password = longPassword.toString();
        
        String hash = passwordEncoder.encode(password);
        assertTrue(passwordEncoder.matches(password, hash), 
                  "Long password should verify correctly");
    }

    @Test
    void testCaseSensitivity() {
        // Test that password verification is case sensitive
        String password = "CaseSensitive123!";
        String hash = passwordEncoder.encode(password);
        
        assertTrue(passwordEncoder.matches(password, hash), 
                  "Original password should verify");
        assertFalse(passwordEncoder.matches(password.toLowerCase(), hash), 
                   "Lowercase version should not verify");
        assertFalse(passwordEncoder.matches(password.toUpperCase(), hash), 
                   "Uppercase version should not verify");
    }

    @Test
    void testHashSecurityProperties() {
        // Test that hash doesn't contain original password
        String password = "securityTest123!";
        String hash = passwordEncoder.encode(password);
        
        assertFalse(hash.contains(password), 
                   "Hash should not contain original password");
        assertFalse(hash.contains(password.toLowerCase()), 
                   "Hash should not contain lowercase password");
        assertFalse(hash.contains(password.toUpperCase()), 
                   "Hash should not contain uppercase password");
    }
}