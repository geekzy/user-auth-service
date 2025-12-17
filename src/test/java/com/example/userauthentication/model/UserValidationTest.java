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

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for User input validation covering email format and password strength requirements.
 * Tests Requirements 1.3 (email format validation) and 1.4 (password strength validation).
 */
@DisplayName("User Input Validation Tests")
class UserValidationTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Nested
    @DisplayName("Email Format Validation Tests")
    class EmailFormatValidationTests {

        @Test
        @DisplayName("Should accept valid email formats")
        void shouldAcceptValidEmailFormats() {
            // Valid email examples
            String[] validEmails = {
                "user@example.com",
                "test.email@domain.org",
                "user+tag@example.co.uk",
                "firstname.lastname@company.com",
                "user123@test-domain.com",
                "a@b.co",
                "user_name@example.net"
            };

            for (String email : validEmails) {
                User user = new User(email, "validPasswordHash123");
                Set<ConstraintViolation<User>> violations = validator.validate(user);
                
                // Filter violations to only email-related ones
                boolean hasEmailViolation = violations.stream()
                    .anyMatch(v -> v.getPropertyPath().toString().equals("email"));
                
                assertThat(hasEmailViolation)
                    .as("Email '%s' should be valid", email)
                    .isFalse();
            }
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "",                    // Empty string
            "   ",                 // Whitespace only
            "invalid-email",       // Missing @ and domain
            "@example.com",        // Missing local part
            "user@",               // Missing domain
            "user@domain",         // Missing TLD
            "user.example.com",    // Missing @
            "user@@example.com",   // Double @
            "user@.com",           // Domain starts with dot
            "user@example.",       // TLD missing
            "user@example..com",   // Double dot in domain
            "user name@example.com", // Space in local part
            "user@exam ple.com",   // Space in domain
            "user@example.c"       // TLD too short
        })
        @DisplayName("Should reject invalid email formats")
        void shouldRejectInvalidEmailFormats(String invalidEmail) {
            User user = new User(invalidEmail, "validPasswordHash123");
            Set<ConstraintViolation<User>> violations = validator.validate(user);
            
            // Check if there's an email-related violation
            boolean hasEmailViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("email"));
            
            assertThat(hasEmailViolation)
                .as("Email '%s' should be invalid", invalidEmail)
                .isTrue();
        }

        @Test
        @DisplayName("Should reject email that exceeds maximum length")
        void shouldRejectEmailThatExceedsMaximumLength() {
            // Create an email longer than 255 characters
            String longLocalPart = "a".repeat(250);
            String tooLongEmail = longLocalPart + "@example.com";
            
            User user = new User(tooLongEmail, "validPasswordHash123");
            Set<ConstraintViolation<User>> violations = validator.validate(user);
            
            boolean hasEmailViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("email"));
            
            assertThat(hasEmailViolation)
                .as("Email with length %d should be invalid", tooLongEmail.length())
                .isTrue();
        }

        @Test
        @DisplayName("Should reject null email")
        void shouldRejectNullEmail() {
            User user = new User(null, "validPasswordHash123");
            Set<ConstraintViolation<User>> violations = validator.validate(user);
            
            boolean hasEmailViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("email"));
            
            assertThat(hasEmailViolation).isTrue();
        }
    }

    @Nested
    @DisplayName("Password Strength Validation Tests")
    class PasswordStrengthValidationTests {

        @Test
        @DisplayName("Should accept strong passwords")
        void shouldAcceptStrongPasswords() {
            String[] strongPasswords = {
                "Password123!",
                "MyStr0ng@Pass",
                "C0mplex#Password",
                "Secure$Pass1",
                "Valid&Password2",
                "Strong*Pass3",
                "Good+Password4",
                "Test_Password5!"
            };

            for (String password : strongPasswords) {
                boolean isStrong = User.isPasswordStrong(password);
                assertThat(isStrong)
                    .as("Password '%s' should be considered strong", password)
                    .isTrue();
            }
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "",                    // Empty string
            "short",               // Too short (less than 8 characters)
            "1234567",             // Only numbers, too short
            "password",            // Only lowercase, no numbers/special chars
            "PASSWORD",            // Only uppercase, no numbers/special chars
            "12345678",            // Only numbers, no letters/special chars
            "!@#$%^&*",            // Only special characters, no letters/numbers
            "Password",            // Missing numbers and special characters
            "Password123",         // Missing special characters
            "Password!@#",         // Missing numbers
            "password123!",        // Missing uppercase
            "PASSWORD123!",        // Missing lowercase
            "Pass1!",              // Too short (6 characters)
            "Short1!"              // Too short (7 characters)
        })
        @DisplayName("Should reject weak passwords")
        void shouldRejectWeakPasswords(String weakPassword) {
            boolean isStrong = User.isPasswordStrong(weakPassword);
            assertThat(isStrong)
                .as("Password '%s' should be considered weak", weakPassword)
                .isFalse();
        }

        @Test
        @DisplayName("Should reject null password")
        void shouldRejectNullPassword() {
            boolean isStrong = User.isPasswordStrong(null);
            assertThat(isStrong).isFalse();
        }

        @Test
        @DisplayName("Should validate password requirements individually")
        void shouldValidatePasswordRequirementsIndividually() {
            // Test minimum length requirement
            assertThat(User.isPasswordStrong("Pass1!")).isFalse(); // 6 chars, too short
            assertThat(User.isPasswordStrong("Password1!")).isTrue(); // 10 chars, meets length

            // Test uppercase requirement
            assertThat(User.isPasswordStrong("password123!")).isFalse(); // No uppercase
            assertThat(User.isPasswordStrong("Password123!")).isTrue(); // Has uppercase

            // Test lowercase requirement
            assertThat(User.isPasswordStrong("PASSWORD123!")).isFalse(); // No lowercase
            assertThat(User.isPasswordStrong("Password123!")).isTrue(); // Has lowercase

            // Test digit requirement
            assertThat(User.isPasswordStrong("Password!")).isFalse(); // No digits
            assertThat(User.isPasswordStrong("Password123!")).isTrue(); // Has digits

            // Test special character requirement
            assertThat(User.isPasswordStrong("Password123")).isFalse(); // No special chars
            assertThat(User.isPasswordStrong("Password123!")).isTrue(); // Has special chars
        }

        @Test
        @DisplayName("Should accept all valid special characters")
        void shouldAcceptAllValidSpecialCharacters() {
            String specialChars = "!@#$%^&*()_+-=[]{}|;:,.<>?";
            
            for (char specialChar : specialChars.toCharArray()) {
                String password = "Password123" + specialChar;
                boolean isStrong = User.isPasswordStrong(password);
                assertThat(isStrong)
                    .as("Password with special character '%c' should be strong", specialChar)
                    .isTrue();
            }
        }

        @Test
        @DisplayName("Should accept minimum length passwords that meet all criteria")
        void shouldAcceptMinimumLengthPasswords() {
            // Test exactly 8 characters - minimum acceptable length
            String[] minimumValidPasswords = {
                "Pass123!",    // Exactly 8 characters, meets all requirements
                "Test456@",    // Exactly 8 characters, meets all requirements
                "Good789#"     // Exactly 8 characters, meets all requirements
            };

            for (String password : minimumValidPasswords) {
                boolean isStrong = User.isPasswordStrong(password);
                assertThat(isStrong)
                    .as("Password '%s' with 8 characters should be considered strong", password)
                    .isTrue();
            }
        }

        @Test
        @DisplayName("Should accept passwords with whitespace")
        void shouldAcceptPasswordsWithWhitespace() {
            // Current implementation doesn't trim or reject whitespace
            // This documents the current behavior - may need to be changed if requirements specify otherwise
            String[] passwordsWithWhitespace = {
                "   Password123!   ",  // Leading and trailing whitespace
                " Password123! ",      // Single spaces
                "Pass word123!",       // Internal space
                "\tPassword123!\t"     // Tab characters
            };

            for (String password : passwordsWithWhitespace) {
                boolean isStrong = User.isPasswordStrong(password);
                assertThat(isStrong)
                    .as("Password '%s' with whitespace should be accepted by current implementation", password)
                    .isTrue();
            }
        }
    }

    @Nested
    @DisplayName("Password Hash Validation Tests")
    class PasswordHashValidationTests {

        @Test
        @DisplayName("Should reject user with invalid password hash length")
        void shouldRejectInvalidPasswordHashLength() {
            // Test password hash that's too short (BCrypt hashes are typically 60 characters)
            User userWithShortHash = new User("user@example.com", "short");
            Set<ConstraintViolation<User>> violations = validator.validate(userWithShortHash);
            
            boolean hasPasswordHashViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("passwordHash"));
            
            assertThat(hasPasswordHashViolation).isTrue();
        }

        @Test
        @DisplayName("Should accept user with valid password hash length")
        void shouldAcceptValidPasswordHashLength() {
            // BCrypt hash example (60 characters)
            String validBCryptHash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";
            User userWithValidHash = new User("user@example.com", validBCryptHash);
            Set<ConstraintViolation<User>> violations = validator.validate(userWithValidHash);
            
            boolean hasPasswordHashViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("passwordHash"));
            
            assertThat(hasPasswordHashViolation).isFalse();
        }

        @Test
        @DisplayName("Should reject null or blank password hash")
        void shouldRejectNullOrBlankPasswordHash() {
            // Test null password hash
            User userWithNullHash = new User("user@example.com", null);
            Set<ConstraintViolation<User>> violations = validator.validate(userWithNullHash);
            
            boolean hasPasswordHashViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("passwordHash"));
            
            assertThat(hasPasswordHashViolation).isTrue();

            // Test blank password hash
            User userWithBlankHash = new User("user@example.com", "   ");
            violations = validator.validate(userWithBlankHash);
            
            hasPasswordHashViolation = violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("passwordHash"));
            
            assertThat(hasPasswordHashViolation).isTrue();
        }
    }
}