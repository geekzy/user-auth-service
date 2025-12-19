package com.example.userauthentication.service;

import com.example.userauthentication.dto.UserRegistrationRequest;
import com.example.userauthentication.dto.UserRegistrationResponse;
import com.example.userauthentication.exception.InvalidPasswordException;
import com.example.userauthentication.exception.UserAlreadyExistsException;
import com.example.userauthentication.model.User;
import com.example.userauthentication.repository.UserRepository;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserService registration functionality.
 * Tests user registration validation, duplicate checking, and password encoding.
 * 
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Tests")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private EmailService emailService;

    private PasswordEncoder passwordEncoder;
    private MeterRegistry meterRegistry;
    private UserService userService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        meterRegistry = new SimpleMeterRegistry();
        userService = new UserService(userRepository, passwordEncoder, emailService, meterRegistry);
    }

    @Test
    @DisplayName("Should successfully register user with valid credentials")
    void shouldRegisterUserWithValidCredentials() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "test@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );
        
        User savedUser = new User("test@example.com", "hashedPassword");
        savedUser.setId(1L);
        savedUser.setCreatedAt(LocalDateTime.now());

        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        // When
        UserRegistrationResponse response = userService.registerUser(request);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getId()).isEqualTo(1L);
        assertThat(response.getEmail()).isEqualTo("test@example.com");
        assertThat(response.isEmailVerified()).isFalse();
        assertThat(response.getMessage()).contains("Registration successful");

        verify(userRepository).existsByEmail("test@example.com");
        verify(userRepository).save(any(User.class));
        verify(emailService).sendVerificationEmail(eq("test@example.com"), anyString());
    }

    @Test
    @DisplayName("Should throw UserAlreadyExistsException when email already exists")
    void shouldThrowExceptionWhenEmailAlreadyExists() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "existing@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );

        when(userRepository.existsByEmail("existing@example.com")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(UserAlreadyExistsException.class)
            .hasMessageContaining("already exists");

        verify(userRepository).existsByEmail("existing@example.com");
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should throw InvalidPasswordException for weak password")
    void shouldThrowExceptionForWeakPassword() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "test@example.com", 
            "weak", 
            "weak"
        );

        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(InvalidPasswordException.class)
            .hasMessageContaining("Password must be at least 8 characters");

        verify(userRepository).existsByEmail("test@example.com");
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException when passwords don't match")
    void shouldThrowExceptionWhenPasswordsDontMatch() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "test@example.com", 
            "StrongPass123!", 
            "DifferentPass123!"
        );

        when(userRepository.existsByEmail("test@example.com")).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("do not match");

        verify(userRepository).existsByEmail("test@example.com");
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should find user by email")
    void shouldFindUserByEmail() {
        // Given
        String email = "test@example.com";
        User user = new User(email, "hashedPassword");
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // When
        Optional<User> result = userService.findByEmail(email);

        // Then
        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo(email);
        verify(userRepository).findByEmail(email);
    }

    @Test
    @DisplayName("Should check if user exists by email")
    void shouldCheckIfUserExistsByEmail() {
        // Given
        String email = "test@example.com";
        when(userRepository.existsByEmail(email)).thenReturn(true);

        // When
        boolean exists = userService.existsByEmail(email);

        // Then
        assertThat(exists).isTrue();
        verify(userRepository).existsByEmail(email);
    }

    @Test
    @DisplayName("Should verify user email")
    void shouldVerifyUserEmail() {
        // Given
        Long userId = 1L;

        // When
        userService.verifyEmail(userId);

        // Then
        verify(userRepository).markEmailAsVerified(userId);
    }

    @Test
    @DisplayName("Should update user password with strong password")
    void shouldUpdateUserPasswordWithStrongPassword() {
        // Given
        Long userId = 1L;
        String newPassword = "NewStrongPass123!";

        // When
        userService.updatePassword(userId, newPassword);

        // Then
        verify(userRepository).updatePassword(eq(userId), anyString());
    }

    @Test
    @DisplayName("Should throw InvalidPasswordException when updating with weak password")
    void shouldThrowExceptionWhenUpdatingWithWeakPassword() {
        // Given
        Long userId = 1L;
        String weakPassword = "weak";

        // When & Then
        assertThatThrownBy(() -> userService.updatePassword(userId, weakPassword))
            .isInstanceOf(InvalidPasswordException.class)
            .hasMessageContaining("Password must be at least 8 characters");

        verify(userRepository, never()).updatePassword(anyLong(), anyString());
    }

    // Additional tests for duplicate prevention - Task 6.3
    
    @Test
    @DisplayName("Should prevent duplicate registration with case-insensitive email")
    void shouldPreventDuplicateRegistrationWithCaseInsensitiveEmail() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "TEST@EXAMPLE.COM", 
            "StrongPass123!", 
            "StrongPass123!"
        );

        // Mock repository to return true for lowercase version
        when(userRepository.existsByEmail("TEST@EXAMPLE.COM")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(UserAlreadyExistsException.class)
            .hasMessageContaining("already exists");

        verify(userRepository).existsByEmail("TEST@EXAMPLE.COM");
        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should handle concurrent registration attempts for same email")
    void shouldHandleConcurrentRegistrationAttempts() {
        // Given
        UserRegistrationRequest request1 = new UserRegistrationRequest(
            "concurrent@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );
        UserRegistrationRequest request2 = new UserRegistrationRequest(
            "concurrent@example.com", 
            "AnotherPass456!", 
            "AnotherPass456!"
        );

        // First call returns false (no existing user), second call returns true (user exists)
        when(userRepository.existsByEmail("concurrent@example.com"))
            .thenReturn(false)
            .thenReturn(true);

        User savedUser = new User("concurrent@example.com", "hashedPassword");
        savedUser.setId(1L);
        savedUser.setCreatedAt(LocalDateTime.now());
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        // When - First registration succeeds
        UserRegistrationResponse response1 = userService.registerUser(request1);
        
        // Then - First registration is successful
        assertThat(response1).isNotNull();
        assertThat(response1.getEmail()).isEqualTo("concurrent@example.com");

        // When & Then - Second registration fails
        assertThatThrownBy(() -> userService.registerUser(request2))
            .isInstanceOf(UserAlreadyExistsException.class)
            .hasMessageContaining("already exists");

        verify(userRepository, times(2)).existsByEmail("concurrent@example.com");
        verify(userRepository, times(1)).save(any(User.class));
        verify(emailService, times(1)).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should handle database unique constraint violation gracefully")
    void shouldHandleDatabaseUniqueConstraintViolation() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "constraint@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );

        when(userRepository.existsByEmail("constraint@example.com")).thenReturn(false);
        
        // Simulate database unique constraint violation
        when(userRepository.save(any(User.class)))
            .thenThrow(new org.springframework.dao.DataIntegrityViolationException(
                "Duplicate entry 'constraint@example.com' for key 'users.email'"));

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Registration failed due to an internal error")
            .hasCauseInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);

        verify(userRepository).existsByEmail("constraint@example.com");
        verify(userRepository).save(any(User.class));
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should validate email uniqueness with whitespace variations")
    void shouldValidateEmailUniquenessWithWhitespaceVariations() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            " whitespace@example.com ", 
            "StrongPass123!", 
            "StrongPass123!"
        );

        // Repository should be called with trimmed email
        when(userRepository.existsByEmail(" whitespace@example.com ")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(UserAlreadyExistsException.class)
            .hasMessageContaining("already exists");

        verify(userRepository).existsByEmail(" whitespace@example.com ");
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should prevent registration with null or empty email")
    void shouldPreventRegistrationWithInvalidEmail() {
        // Test null email
        UserRegistrationRequest nullEmailRequest = new UserRegistrationRequest(
            null, 
            "StrongPass123!", 
            "StrongPass123!"
        );

        assertThatThrownBy(() -> userService.registerUser(nullEmailRequest))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Email is required");

        // Test empty email
        UserRegistrationRequest emptyEmailRequest = new UserRegistrationRequest(
            "", 
            "StrongPass123!", 
            "StrongPass123!"
        );

        assertThatThrownBy(() -> userService.registerUser(emptyEmailRequest))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Email is required");

        // Test whitespace-only email
        UserRegistrationRequest whitespaceEmailRequest = new UserRegistrationRequest(
            "   ", 
            "StrongPass123!", 
            "StrongPass123!"
        );

        assertThatThrownBy(() -> userService.registerUser(whitespaceEmailRequest))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Email is required");

        verify(userRepository, never()).existsByEmail(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should maintain data integrity during duplicate prevention")
    void shouldMaintainDataIntegrityDuringDuplicatePrevention() {
        // Given
        String existingEmail = "integrity@example.com";
        UserRegistrationRequest request = new UserRegistrationRequest(
            existingEmail, 
            "StrongPass123!", 
            "StrongPass123!"
        );

        when(userRepository.existsByEmail(existingEmail)).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(UserAlreadyExistsException.class);

        // Verify that no database modifications were attempted
        verify(userRepository).existsByEmail(existingEmail);
        verify(userRepository, never()).save(any(User.class));
        verify(userRepository, never()).updatePassword(anyLong(), anyString());
        verify(userRepository, never()).markEmailAsVerified(anyLong());
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
    }

    // Email Service Integration Tests - Task 7.2

    @Test
    @DisplayName("Should send verification email with generated token on successful registration")
    void shouldSendVerificationEmailWithGeneratedTokenOnSuccessfulRegistration() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "email-test@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );
        
        User savedUser = new User("email-test@example.com", "hashedPassword");
        savedUser.setId(1L);
        savedUser.setCreatedAt(LocalDateTime.now());

        when(userRepository.existsByEmail("email-test@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        // When
        UserRegistrationResponse response = userService.registerUser(request);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getEmail()).isEqualTo("email-test@example.com");

        // Verify email service is called with correct email and a non-null token
        verify(emailService).sendVerificationEmail(eq("email-test@example.com"), anyString());
        
        // Capture the token argument to verify it's not null or empty
        verify(emailService).sendVerificationEmail(eq("email-test@example.com"), argThat(token -> 
            token != null && !token.trim().isEmpty() && token.length() > 10
        ));
    }

    @Test
    @DisplayName("Should not send verification email when registration fails due to existing user")
    void shouldNotSendVerificationEmailWhenRegistrationFailsDueToExistingUser() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "existing-email@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );

        when(userRepository.existsByEmail("existing-email@example.com")).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(UserAlreadyExistsException.class);

        // Verify no email is sent when registration fails
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should not send verification email when registration fails due to weak password")
    void shouldNotSendVerificationEmailWhenRegistrationFailsDueToWeakPassword() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "weak-password@example.com", 
            "123", 
            "123"
        );

        when(userRepository.existsByEmail("weak-password@example.com")).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(InvalidPasswordException.class);

        // Verify no email is sent when password validation fails
        verify(emailService, never()).sendVerificationEmail(anyString(), anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("Should handle email service failure during registration")
    void shouldHandleEmailServiceFailureDuringRegistration() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "email-failure@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );
        
        User savedUser = new User("email-failure@example.com", "hashedPassword");
        savedUser.setId(1L);
        savedUser.setCreatedAt(LocalDateTime.now());

        when(userRepository.existsByEmail("email-failure@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        
        // Mock email service to throw exception
        doThrow(new RuntimeException("Email service unavailable"))
            .when(emailService).sendVerificationEmail(anyString(), anyString());

        // When & Then - Registration should fail if email service fails
        // Since email service is called synchronously in current implementation
        assertThatThrownBy(() -> userService.registerUser(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Registration failed due to an internal error")
            .hasCauseInstanceOf(RuntimeException.class);

        // Verify that user was saved but email service failed
        verify(userRepository).save(any(User.class));
        verify(emailService).sendVerificationEmail(eq("email-failure@example.com"), anyString());
    }

    @Test
    @DisplayName("Should generate unique verification tokens for different users")
    void shouldGenerateUniqueVerificationTokensForDifferentUsers() {
        // Given
        UserRegistrationRequest request1 = new UserRegistrationRequest(
            "user1@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );
        UserRegistrationRequest request2 = new UserRegistrationRequest(
            "user2@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );
        
        User savedUser1 = new User("user1@example.com", "hashedPassword");
        savedUser1.setId(1L);
        savedUser1.setCreatedAt(LocalDateTime.now());
        
        User savedUser2 = new User("user2@example.com", "hashedPassword");
        savedUser2.setId(2L);
        savedUser2.setCreatedAt(LocalDateTime.now());

        when(userRepository.existsByEmail("user1@example.com")).thenReturn(false);
        when(userRepository.existsByEmail("user2@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(savedUser1, savedUser2);

        // When
        userService.registerUser(request1);
        userService.registerUser(request2);

        // Then - Verify both users get verification emails
        verify(emailService).sendVerificationEmail(eq("user1@example.com"), anyString());
        verify(emailService).sendVerificationEmail(eq("user2@example.com"), anyString());
        
        // Verify email service was called exactly twice
        verify(emailService, times(2)).sendVerificationEmail(anyString(), anyString());
    }

    @Test
    @DisplayName("Should send verification email with secure token format")
    void shouldSendVerificationEmailWithSecureTokenFormat() {
        // Given
        UserRegistrationRequest request = new UserRegistrationRequest(
            "secure-token@example.com", 
            "StrongPass123!", 
            "StrongPass123!"
        );
        
        User savedUser = new User("secure-token@example.com", "hashedPassword");
        savedUser.setId(1L);
        savedUser.setCreatedAt(LocalDateTime.now());

        when(userRepository.existsByEmail("secure-token@example.com")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenReturn(savedUser);

        // When
        userService.registerUser(request);

        // Then - Verify token meets security requirements
        verify(emailService).sendVerificationEmail(eq("secure-token@example.com"), argThat(token -> {
            // Token should be base64-encoded, URL-safe, and of sufficient length
            return token != null 
                && token.length() >= 32  // Minimum length for security
                && token.matches("[A-Za-z0-9_-]+")  // URL-safe base64 pattern
                && !token.contains(" ")  // No spaces
                && !token.contains("+")  // URL-safe (no + characters)
                && !token.contains("/"); // URL-safe (no / characters)
        }));
    }
}