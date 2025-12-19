# Implementation Plan

- [x] 1. Set up Spring Boot project structure and dependencies
  - Create Spring Boot project with Maven/Gradle build configuration
  - Add dependencies for Spring Security, Spring Data JPA, MariaDB connector, BCrypt
  - Configure application.properties for MariaDB connection and security settings
  - Set up testing framework with JUnit 5 and Mockito for unit testing
  - Add Micrometer and Actuator dependencies for performance metrics
  - _Requirements: 1.1, 2.1, 4.1, 5.1_

- [x] 2. Create MariaDB database schema and JPA entities
  - [x] 2.1 Set up MariaDB database and connection configuration
    - Create database schema with proper indexing for performance
    - Configure HikariCP connection pool for optimal performance
    - Add database migration scripts using Flyway
    - _Requirements: 1.1, 2.1, 4.1_

  - [x] 2.2 Create User JPA entity with validation
    - Implement User entity with JPA annotations and Bean Validation
    - Add email format validation and password strength checking
    - Configure database constraints and indexes
    - _Requirements: 1.1, 1.3, 1.4_

  - [x] 2.3 Write unit tests for input validation
    - Test email format validation with valid and invalid examples
    - Test password strength validation with various password combinations
    - _Requirements: 1.3, 1.4_

  - [x] 2.4 Create Session JPA entity with lifecycle management
    - Implement Session entity with automatic expiration handling
    - Add JPA lifecycle callbacks for session management
    - Configure session cleanup scheduled tasks
    - _Requirements: 2.1, 6.1, 6.2_

  - [x] 2.5 Write unit tests for session lifecycle
    - Test session creation, extension, and expiration scenarios
    - Test session cleanup and validation edge cases
    - _Requirements: 6.1, 6.2_

  - [x] 2.6 Create PasswordResetToken JPA entity
    - Implement token entity with expiration and single-use enforcement
    - Add database constraints for token uniqueness
    - Configure automatic token cleanup
    - _Requirements: 4.1, 4.4, 4.5_

  - [x] 2.7 Write unit tests for reset token behavior
    - Test token generation, expiration, and single-use enforcement
    - Test token validation and cleanup scenarios
    - _Requirements: 4.5_

- [x] 3. Implement Spring Security configuration and services
  - [x] 3.1 Configure Spring Security with custom authentication
    - Set up SecurityConfig with BCryptPasswordEncoder
    - Configure authentication providers and security filters
    - Add CORS and CSRF protection configuration
    - _Requirements: 5.1, 5.2_

  - [x] 3.2 Write unit tests for password hashing
    - Test BCrypt password encoding and verification
    - Test password hash uniqueness and security
    - _Requirements: 5.1_

  - [x] 3.3 Create JWT token service for session management
    - Implement JWT token generation and validation
    - Add token refresh and blacklist functionality
    - Configure token expiration and security settings
    - _Requirements: 4.1, 5.3, 6.1_

  - [x] 3.4 Write unit tests for token generation
    - Test JWT token generation and validation
    - Test token uniqueness and security properties
    - _Requirements: 5.3_

  - [x] 3.5 Implement rate limiting with Redis/In-memory cache
    - Create rate limiting interceptor using Spring AOP
    - Add configurable limits with sliding window algorithm
    - Integrate with Spring Cache for performance
    - _Requirements: 5.4_

  - [x] 3.6 Write unit tests for rate limiting
    - Test rate limiting enforcement and threshold behavior
    - Test rate limit reset and sliding window functionality
    - _Requirements: 5.4_

- [ ] 4. Set up performance monitoring and metrics
  - [x] 4.1 Configure Micrometer and Actuator endpoints
    - Set up Micrometer with Prometheus registry for metrics collection
    - Configure Actuator endpoints for health checks and monitoring
    - Add custom metrics for authentication operations
    - _Requirements: All requirements (performance monitoring)_

  - [x] 4.2 Implement performance logging and monitoring
    - Add method-level performance monitoring using @Timed annotations
    - Configure database connection pool metrics
    - Set up authentication success/failure rate metrics
    - _Requirements: 2.1, 2.2, 5.5_

  - [ ] 4.3 Create performance test benchmarks
    - Implement JMH benchmarks for critical authentication paths
    - Add load testing scenarios for concurrent authentication
    - Configure performance thresholds and alerts
    - _Requirements: 2.1, 2.5, 5.4_

- [x] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 6. Implement Spring Data JPA repositories
  - [x] 6.1 Create UserRepository with custom queries
    - Implement JpaRepository with custom query methods
    - Add optimized queries for email lookup and login timestamp updates
    - Configure query performance monitoring and caching
    - _Requirements: 1.1, 1.2, 2.4_

  - [ ]* 6.2 Write unit tests for user registration
    - Test successful user registration with valid credentials
    - Test registration validation and error handling
    - _Requirements: 1.1_

  - [ ]* 6.3 Write unit tests for duplicate prevention
    - Test duplicate email detection and prevention
    - Test unique constraint enforcement and error handling
    - _Requirements: 1.2_

  - [x] 6.4 Create SessionRepository with cleanup scheduling
    - Implement repository with automatic session cleanup
    - Add batch operations for session management
    - Configure database indexes for session queries
    - _Requirements: 2.1, 3.1, 6.1, 6.2_

  - [x] 6.5 Create AuditLogRepository for security events
    - Implement repository for security event logging
    - Add efficient querying and archival capabilities
    - Configure async logging for performance
    - _Requirements: 3.4, 5.5_

  - [ ]* 6.6 Write unit tests for audit logging
    - Test security event logging and timestamp recording
    - Test log entry creation and retrieval functionality
    - _Requirements: 3.4, 5.5_

- [ ] 7. Implement authentication service layer
  - [ ] 7.1 Create UserService with registration functionality
    - Implement @Service class with @Transactional methods
    - Add email validation, duplicate checking, and password encoding
    - Integrate with email service for verification
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [ ]* 7.2 Write unit tests for registration email
    - Test email verification sending and template rendering
    - Test email service integration and error handling
    - _Requirements: 1.5_

  - [ ] 7.3 Create AuthenticationService with login functionality
    - Implement Spring Security authentication with custom logic
    - Add failed attempt tracking and account locking mechanisms
    - Integrate with JWT token generation and metrics
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ]* 7.4 Write unit tests for valid login
    - Test successful login with valid credentials and session creation
    - Test authentication flow and JWT token generation
    - _Requirements: 2.1_

  - [ ]* 7.5 Write unit tests for login rejection
    - Test invalid credential rejection and error messages
    - Test unverified email login prevention
    - _Requirements: 2.2, 2.3_

  - [ ]* 7.6 Write unit tests for login timestamps
    - Test login timestamp recording and last access updates
    - Test timestamp accuracy and database persistence
    - _Requirements: 2.4_

  - [ ]* 7.7 Write unit tests for account locking
    - Test account locking after multiple failed login attempts
    - Test lockout duration and unlock mechanisms
    - _Requirements: 2.5_

  - [ ] 7.8 Create SessionService with logout functionality
    - Implement session management with JWT blacklisting
    - Add audit logging and performance metrics
    - Configure async session cleanup
    - _Requirements: 3.1, 3.3, 3.4_

  - [ ]* 7.9 Write unit tests for session invalidation
    - Test session invalidation and JWT blacklisting on logout
    - Test session cleanup and token removal
    - _Requirements: 3.1_

  - [ ]* 7.10 Write unit tests for post-logout access
    - Test access denial to protected resources after logout
    - Test authentication filter behavior with invalid tokens
    - _Requirements: 3.3_

- [ ] 8. Implement password reset functionality
  - [ ] 8.1 Create PasswordResetService with request handling
    - Implement @Service with secure token generation
    - Add silent handling for unregistered emails with consistent timing
    - Integrate with email service and rate limiting
    - _Requirements: 4.1, 4.2_

  - [ ]* 8.2 Write unit tests for reset token generation
    - Test password reset token generation and email sending
    - Test token security and expiration handling
    - _Requirements: 4.1_

  - [ ]* 8.3 Write unit tests for silent email handling
    - Test silent handling of password reset for unregistered emails
    - Test consistent response timing and no information leakage
    - _Requirements: 4.2_

  - [ ] 8.4 Create password reset completion functionality
    - Implement token validation and password update
    - Add @Transactional token invalidation after successful reset
    - Configure performance monitoring for reset operations
    - _Requirements: 4.4, 4.5_

  - [ ]* 8.5 Write unit tests for password reset completion
    - Test password reset completion with valid tokens
    - Test token invalidation and password update verification
    - _Requirements: 4.4_

- [ ] 9. Implement session management and security features
  - [ ] 9.1 Create JWT authentication filter
    - Implement OncePerRequestFilter for JWT validation
    - Add automatic session extension and blacklist checking
    - Configure filter chain with performance monitoring
    - _Requirements: 6.1, 6.2_

  - [ ] 9.2 Create DeviceDetectionService with notification
    - Implement device fingerprinting and detection logic
    - Add async security notification email sending
    - Configure device tracking with privacy considerations
    - _Requirements: 6.5_

  - [ ]* 9.3 Write unit tests for device notifications
    - Test new device detection and notification sending
    - Test device fingerprinting and security alert functionality
    - _Requirements: 6.5_

- [ ] 10. Create REST controllers with Spring Boot
  - [ ] 10.1 Implement AuthController with registration endpoint
    - Create @RestController with @PostMapping for /api/auth/register
    - Add @Valid request body validation and proper error handling
    - Configure response DTOs and HTTP status codes
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [ ] 10.2 Implement login endpoint with security
    - Create POST /api/auth/login with @RateLimited annotation
    - Add JWT token generation and security headers
    - Configure authentication success/failure metrics
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ] 10.3 Implement logout endpoint with cleanup
    - Create POST /api/auth/logout with JWT blacklisting
    - Add proper response handling and audit logging
    - Configure async session cleanup
    - _Requirements: 3.1, 3.3, 3.4_

  - [ ] 10.4 Implement password reset endpoints
    - Create POST /api/auth/reset-request and /api/auth/reset-confirm
    - Add comprehensive validation and security measures
    - Configure rate limiting and performance monitoring
    - _Requirements: 4.1, 4.2, 4.4, 4.5_

  - [ ] 10.5 Implement session validation endpoint
    - Create GET /api/auth/session with JWT validation
    - Add session extension and health check logic
    - Configure caching for performance optimization
    - _Requirements: 6.1, 6.2_

- [ ] 11. Create Thymeleaf templates and frontend integration
  - [ ] 11.1 Create registration page with Thymeleaf
    - Implement registration form template with server-side validation
    - Add Bootstrap styling and client-side validation
    - Configure CSRF protection and error display
    - _Requirements: 1.1, 1.3, 1.4_

  - [ ] 11.2 Create login page with security features
    - Implement login form template with credential input
    - Add "remember me" functionality and error handling
    - Configure rate limiting display and account lockout messages
    - _Requirements: 2.1, 2.2, 6.3_

  - [ ] 11.3 Create password reset page templates
    - Implement reset request and confirmation form templates
    - Add proper validation feedback and user guidance
    - Configure secure token handling in URLs
    - _Requirements: 4.1, 4.3, 4.4_

  - [ ] 11.4 Create authentication state management
    - Implement JavaScript for JWT token handling
    - Add automatic logout on token expiration
    - Configure axios interceptors for API authentication
    - _Requirements: 3.3, 6.2_

- [ ] 12. Implement Spring Boot email service integration
  - [ ] 12.1 Configure JavaMailSender with email templates
    - Set up Spring Boot mail configuration with SMTP
    - Create Thymeleaf email templates for verification
    - Add async email sending with @Async annotation
    - _Requirements: 1.5_

  - [ ] 12.2 Create password reset email service
    - Implement email service with secure reset links
    - Add HTML email templates with proper styling
    - Configure email delivery monitoring and retry logic
    - _Requirements: 4.1_

  - [ ] 12.3 Create security notification email service
    - Implement new device login notification system
    - Add security alert templates with device information
    - Configure email rate limiting and delivery tracking
    - _Requirements: 6.5_

- [ ] 13. Add comprehensive error handling and security
  - [ ] 13.1 Implement @ControllerAdvice global exception handler
    - Create centralized exception handling for all controllers
    - Add proper error logging with structured logging (Logback)
    - Configure user-friendly error responses and security headers
    - _Requirements: All requirements_

  - [ ] 13.2 Add input sanitization and validation
    - Implement comprehensive Bean Validation across all DTOs
    - Add XSS prevention with OWASP Java Encoder
    - Configure SQL injection prevention with JPA parameterized queries
    - _Requirements: 1.3, 1.4, 5.4_

  - [ ] 13.3 Configure production security settings
    - Set up HTTPS configuration and security headers
    - Configure database connection encryption
    - Add application security monitoring and alerting
    - _Requirements: 5.1, 5.2, 5.4, 5.5_

- [ ] 14. Performance optimization and monitoring setup
  - [ ] 14.1 Configure database performance optimization
    - Set up connection pool tuning and query optimization
    - Add database query performance monitoring
    - Configure read replicas for scaling (if needed)
    - _Requirements: All requirements (performance)_

  - [ ] 14.2 Set up application performance monitoring
    - Configure APM with Micrometer and Prometheus
    - Add custom business metrics dashboards
    - Set up alerting for performance thresholds
    - _Requirements: All requirements (monitoring)_

- [ ] 15. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.