package com.example.userauthentication.service;

import com.example.userauthentication.dto.UserRegistrationRequest;
import com.example.userauthentication.dto.UserRegistrationResponse;
import com.example.userauthentication.exception.InvalidPasswordException;
import com.example.userauthentication.exception.UserAlreadyExistsException;
import com.example.userauthentication.model.User;
import com.example.userauthentication.repository.UserRepository;
import io.micrometer.core.annotation.Timed;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;

/**
 * Service class for user management operations.
 * Handles user registration, validation, and email verification.
 * 
 * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
 */
@Service
@Transactional
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final Counter registrationAttempts;
    private final Counter registrationSuccesses;
    private final Counter registrationFailures;
    private final SecureRandom secureRandom;

    public UserService(UserRepository userRepository, 
                      PasswordEncoder passwordEncoder,
                      EmailService emailService,
                      MeterRegistry meterRegistry) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.emailService = emailService;
        this.secureRandom = new SecureRandom();
        
        // Initialize metrics
        this.registrationAttempts = Counter.builder("user.registration.attempts")
                .description("Total number of user registration attempts")
                .register(meterRegistry);
        this.registrationSuccesses = Counter.builder("user.registration.successes")
                .description("Total number of successful user registrations")
                .register(meterRegistry);
        this.registrationFailures = Counter.builder("user.registration.failures")
                .description("Total number of failed user registrations")
                .register(meterRegistry);
    }

    /**
     * Registers a new user with email and password validation.
     * 
     * @param request the user registration request containing email and password
     * @return UserRegistrationResponse with user details and success message
     * @throws UserAlreadyExistsException if email is already registered
     * @throws InvalidPasswordException if password doesn't meet requirements
     * @throws IllegalArgumentException if passwords don't match
     */
    @Timed(value = "user.registration.duration", description = "Time taken to register a user")
    public UserRegistrationResponse registerUser(UserRegistrationRequest request) {
        registrationAttempts.increment();
        
        try {
            logger.info("Starting user registration for email: {}", request.getEmail());
            
            // Validate input
            validateRegistrationRequest(request);
            
            // Check if user already exists
            if (userRepository.existsByEmail(request.getEmail())) {
                logger.warn("Registration attempt with existing email: {}", request.getEmail());
                registrationFailures.increment();
                throw new UserAlreadyExistsException("A user with this email address already exists");
            }
            
            // Validate password strength
            if (!User.isPasswordStrong(request.getPassword())) {
                logger.warn("Registration attempt with weak password for email: {}", request.getEmail());
                registrationFailures.increment();
                throw new InvalidPasswordException(
                    "Password must be at least 8 characters long and contain at least one uppercase letter, " +
                    "one lowercase letter, one digit, and one special character"
                );
            }
            
            // Check password confirmation
            if (!request.isPasswordConfirmed()) {
                logger.warn("Registration attempt with mismatched passwords for email: {}", request.getEmail());
                registrationFailures.increment();
                throw new IllegalArgumentException("Password and confirmation password do not match");
            }
            
            // Create and save user
            User user = createUser(request.getEmail(), request.getPassword());
            User savedUser = userRepository.save(user);
            
            // Generate verification token and send email
            String verificationToken = generateVerificationToken();
            emailService.sendVerificationEmail(savedUser.getEmail(), verificationToken);
            
            registrationSuccesses.increment();
            logger.info("User registration successful for email: {} with ID: {}", 
                       savedUser.getEmail(), savedUser.getId());
            
            return UserRegistrationResponse.success(
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getEmailVerified(),
                savedUser.getCreatedAt()
            );
            
        } catch (UserAlreadyExistsException | InvalidPasswordException | IllegalArgumentException e) {
            // These are expected validation errors, re-throw them
            throw e;
        } catch (Exception e) {
            registrationFailures.increment();
            logger.error("Unexpected error during user registration for email: {}", request.getEmail(), e);
            throw new RuntimeException("Registration failed due to an internal error", e);
        }
    }

    /**
     * Finds a user by email address.
     * 
     * @param email the email address to search for
     * @return Optional containing the user if found
     */
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        logger.debug("Finding user by email: {}", email);
        return userRepository.findByEmail(email);
    }

    /**
     * Checks if a user exists with the given email.
     * 
     * @param email the email address to check
     * @return true if user exists
     */
    @Transactional(readOnly = true)
    public boolean existsByEmail(String email) {
        logger.debug("Checking if user exists with email: {}", email);
        return userRepository.existsByEmail(email);
    }

    /**
     * Marks a user's email as verified.
     * 
     * @param userId the ID of the user to verify
     */
    public void verifyEmail(Long userId) {
        logger.info("Verifying email for user ID: {}", userId);
        userRepository.markEmailAsVerified(userId);
    }

    /**
     * Updates a user's password.
     * 
     * @param userId the ID of the user
     * @param newPassword the new password (plain text)
     */
    public void updatePassword(Long userId, String newPassword) {
        logger.info("Updating password for user ID: {}", userId);
        
        if (!User.isPasswordStrong(newPassword)) {
            throw new InvalidPasswordException(
                "Password must be at least 8 characters long and contain at least one uppercase letter, " +
                "one lowercase letter, one digit, and one special character"
            );
        }
        
        String hashedPassword = passwordEncoder.encode(newPassword);
        userRepository.updatePassword(userId, hashedPassword);
    }

    /**
     * Validates the registration request input.
     * 
     * @param request the registration request to validate
     * @throws IllegalArgumentException if validation fails
     */
    private void validateRegistrationRequest(UserRegistrationRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Registration request cannot be null");
        }
        
        if (request.getEmail() == null || request.getEmail().trim().isEmpty()) {
            throw new IllegalArgumentException("Email is required");
        }
        
        if (request.getPassword() == null || request.getPassword().isEmpty()) {
            throw new IllegalArgumentException("Password is required");
        }
        
        if (request.getConfirmPassword() == null || request.getConfirmPassword().isEmpty()) {
            throw new IllegalArgumentException("Password confirmation is required");
        }
    }

    /**
     * Creates a new User entity with encoded password.
     * 
     * @param email the user's email
     * @param password the user's plain text password
     * @return the created User entity
     */
    private User createUser(String email, String password) {
        String hashedPassword = passwordEncoder.encode(password);
        return new User(email, hashedPassword);
    }

    /**
     * Generates a secure verification token.
     * 
     * @return a base64-encoded random token
     */
    private String generateVerificationToken() {
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}