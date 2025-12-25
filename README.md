# User Authentication Service

A secure, production-ready user authentication system built with Spring Boot, providing comprehensive identity verification and session management capabilities.

## 🚀 Features

- **User Registration**: Secure account creation with email verification
- **Authentication**: Login/logout with JWT token-based sessions
- **Password Management**: Secure password reset with email-based tokens
- **Security**: Rate limiting, account locking, and brute force protection
- **Session Management**: Automatic session extension and device detection
- **Performance Monitoring**: Comprehensive metrics and health checks
- **Audit Logging**: Security event tracking and monitoring

## 🏗️ Architecture

The system follows a three-tier architecture with clear separation of concerns:

- **Presentation Layer**: REST APIs and Thymeleaf templates
- **Business Logic Layer**: Authentication services and security enforcement
- **Data Access Layer**: JPA repositories with MariaDB persistence

## 📋 Requirements

- Java 17+
- Maven 3.6+
- MariaDB 10.5+
- SMTP server (for email notifications)

## 🛠️ Technology Stack

### Core Framework
- **Spring Boot 3.2.0**: Application framework
- **Spring Security**: Authentication and authorization
- **Spring Data JPA**: Data persistence
- **Thymeleaf**: Server-side templating

### Database & Migration
- **MariaDB**: Primary database
- **Flyway**: Database migration management
- **HikariCP**: Connection pooling

### Security & JWT
- **BCrypt**: Password hashing
- **JJWT**: JWT token management
- **Spring Security Crypto**: Cryptographic operations

### Monitoring & Metrics
- **Micrometer**: Application metrics
- **Prometheus**: Metrics collection
- **Spring Boot Actuator**: Health checks and monitoring

### Testing
- **JUnit 5**: Unit testing framework
- **Mockito**: Mocking framework
- **jqwik**: Property-based testing
- **JMH**: Performance benchmarking
- **H2**: In-memory testing database

## 🚀 Quick Start

### 1. Database Setup

Create a MariaDB database and user:

```sql
CREATE DATABASE user_auth_db;
CREATE USER 'auth_user'@'localhost' IDENTIFIED BY 'auth_password';
GRANT ALL PRIVILEGES ON user_auth_db.* TO 'auth_user'@'localhost';
FLUSH PRIVILEGES;
```

### 2. Development Configuration

For local development, copy the template and fill in your actual credentials:

```bash
# Copy the template
cp src/main/resources/application-dev.properties.template src/main/resources/application-dev.properties

# Edit the file with your actual credentials
# src/main/resources/application-dev.properties
```

Example configuration:
```properties
# Database Configuration
spring.datasource.url=jdbc:mariadb://localhost:3316/backendb
spring.datasource.username=root
spring.datasource.password=your-db-password

# Security Configuration
app.security.jwt.secret=your-very-long-secure-secret-key-here

# Email Configuration (Brevo/Sendinblue or your SMTP provider)
spring.mail.username=your-smtp-username
spring.mail.password=your-smtp-password
app.email.from=Your Name <your-email@example.com>
```

**Note**: The `application-dev.properties` file is excluded from version control for security.

### 3. Run the Application

```bash
# Clone and navigate to project
git clone <repository-url>
cd user-auth-service

# Run with development profile
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Or build and run JAR
mvn clean package
java -jar target/user-auth-service-0.0.1-SNAPSHOT.jar --spring.profiles.active=dev
```

The application will start on `http://localhost:8080`

### 4. Environment Variables (Alternative)

Instead of creating `application-dev.properties`, you can set environment variables:

```bash
export DATABASE_URL=jdbc:mariadb://localhost:3316/backendb
export DATABASE_USERNAME=root
export DATABASE_PASSWORD=your-db-password
export JWT_SECRET=your-very-long-secure-secret-key-here
export SMTP_USERNAME=your-smtp-username
export SMTP_PASSWORD=your-smtp-password
export EMAIL_FROM="Your Name <your-email@example.com>"

mvn spring-boot:run
```

## 📚 API Documentation

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new user account |
| POST | `/api/auth/login` | Authenticate user and create session |
| POST | `/api/auth/logout` | Invalidate current session |
| POST | `/api/auth/reset-request` | Request password reset |
| POST | `/api/auth/reset-confirm` | Confirm password reset with token |
| GET | `/api/auth/session` | Validate current session |

### Example Requests

#### User Registration
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

#### User Login
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePassword123!"
  }'
```

## 🔧 Configuration

### Security Settings

```properties
# JWT Configuration
app.security.jwt.expiration=86400000  # 24 hours
app.security.password.bcrypt.rounds=12

# Rate Limiting
app.security.rate-limit.max-attempts=5
app.security.rate-limit.window-minutes=15

# Account Locking
app.security.account-lock.duration-minutes=30
```

### Session Management

```properties
# Session Configuration
app.session.timeout-minutes=30
app.session.extend-on-activity=true
app.session.remember-me-duration-days=30
```

### Email Configuration

```properties
# SMTP Settings
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=${EMAIL_USERNAME}
spring.mail.password=${EMAIL_PASSWORD}
```

## 🧪 Testing

The project includes comprehensive testing with both unit tests and property-based tests.

### Run All Tests
```bash
mvn test
```

### Run Specific Test Categories
```bash
# Unit tests only
mvn test -Dtest="*Test"

# Property-based tests only
mvn test -Dtest="*Properties"

# Performance test suite
mvn test -Dtest=PerformanceTestSuite

# JMH benchmarks
mvn test -P performance-tests
```

### Testing Strategy

- **Unit Tests**: Verify specific scenarios and edge cases
- **Property-Based Tests**: Verify universal properties across all inputs using jqwik
- **Integration Tests**: Test component interactions
- **Performance Tests**: JMH benchmarks and load testing for critical paths

## 🚀 Performance Testing

The project includes comprehensive performance testing with JMH benchmarks and load testing scenarios.

### Performance Test Components

#### JMH Benchmarks
- **AuthenticationBenchmark**: Single-threaded microbenchmarks for core operations
- **ConcurrentAuthenticationBenchmark**: Multi-threaded benchmarks for concurrent scenarios

#### Load Testing
- **LoadTestScenarios**: Realistic load testing scenarios
- **PerformanceTestSuite**: JUnit integration tests validating performance thresholds

### Running Performance Tests

#### JMH Benchmarks
```bash
# Run all benchmarks
mvn test-compile exec:java -Dexec.mainClass="com.example.userauthentication.benchmark.BenchmarkRunner" -Dexec.args="all"

# Single-threaded benchmarks only
mvn test-compile exec:java -Dexec.mainClass="com.example.userauthentication.benchmark.BenchmarkRunner" -Dexec.args="single"

# Concurrent benchmarks only
mvn test-compile exec:java -Dexec.mainClass="com.example.userauthentication.benchmark.BenchmarkRunner" -Dexec.args="concurrent"
```

#### Load Testing
```bash
# Run performance test suite
mvn test -Dtest=PerformanceTestSuite

# Run with performance profile
mvn test -P performance-tests
```

### Performance Thresholds

#### Single-Threaded Operations (Average Time)
- JWT Token Generation: ≤ 500 μs
- JWT Token Validation: ≤ 200 μs
- Password Hashing: ≤ 100ms
- Password Verification: ≤ 100ms
- Rate Limiting Check: ≤ 100 μs

#### Concurrent Operations (Throughput)
- JWT Generation: ≥ 10,000 ops/sec
- JWT Validation: ≥ 50,000 ops/sec
- Password Verification: ≥ 100 ops/sec
- Rate Limiting: ≥ 100,000 ops/sec
- Mixed Operations: ≥ 5,000 ops/sec

#### System Performance
- Authentication Success Rate: ≥ 95%
- Average Authentication Time: ≤ 200ms
- Connection Pool Utilization: ≤ 80%

### Performance Reports
Detailed reports are generated in `target/performance-report-{timestamp}.txt` with:
- Benchmark results vs thresholds
- Performance alerts for violations
- Detailed metrics and analysis

## 📊 Monitoring & Metrics

### Health Checks
- Application health: `GET /actuator/health`
- Database connectivity: Included in health endpoint
- Disk space: Included in health endpoint

### Metrics Endpoints
- Prometheus metrics: `GET /actuator/prometheus`
- Application metrics: `GET /actuator/metrics`
- Environment info: `GET /actuator/env`

### Custom Metrics
- Authentication success/failure rates
- JWT token generation/validation times
- Database operation durations
- Rate limiting statistics

## 🔒 Security Features

### Password Security
- BCrypt hashing with configurable rounds
- Password strength validation
- Secure password reset tokens

### Session Security
- JWT-based stateless sessions
- Automatic session extension
- Session invalidation on logout
- Device detection and notifications

### Attack Prevention
- Rate limiting on sensitive endpoints
- Account locking after failed attempts
- Timing attack prevention
- CSRF protection
- XSS prevention

### Audit & Logging
- Security event logging
- Failed authentication tracking
- Performance monitoring
- Structured logging with Logback

## 🚀 Deployment

### Production Configuration

1. **Environment Variables**:
```bash
export EMAIL_USERNAME=your-production-email
export EMAIL_PASSWORD=your-production-password
export JWT_SECRET=your-production-jwt-secret
```

2. **Database Configuration**:
```properties
spring.datasource.url=jdbc:mariadb://prod-db:3306/user_auth_db
spring.jpa.hibernate.ddl-auto=validate
```

3. **Security Headers**:
```properties
server.ssl.enabled=true
server.ssl.key-store=classpath:keystore.p12
server.ssl.key-store-password=password
```

### Docker Deployment

```dockerfile
FROM openjdk:17-jre-slim
COPY target/user-auth-service-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app.jar"]
```

## 🔧 Development Guidelines

### Code Style
- Follow Spring Boot conventions
- Use meaningful variable and method names
- Include comprehensive JavaDoc for public APIs
- Maintain test coverage above 80%

### Security Guidelines
- Never log sensitive information (passwords, tokens)
- Use parameterized queries to prevent SQL injection
- Validate all input data
- Implement proper error handling without information leakage

### Testing Guidelines
- Write both unit tests and property-based tests
- Test security-critical functionality thoroughly
- Use realistic test data generators
- Include performance benchmarks for critical paths

### Performance Guidelines
- Use connection pooling for database access
- Implement caching for frequently accessed data
- Monitor and optimize slow database queries
- Use async processing for non-critical operations

## 📁 Project Structure

```
src/
├── main/
│   ├── java/com/example/userauthentication/
│   │   ├── aspect/           # AOP aspects for monitoring
│   │   ├── config/           # Configuration classes
│   │   ├── controller/       # REST controllers
│   │   ├── dto/              # Data transfer objects
│   │   ├── model/            # JPA entities
│   │   ├── repository/       # Data access layer
│   │   ├── security/         # Security components
│   │   └── service/          # Business logic layer
│   └── resources/
│       ├── db/migration/     # Flyway migration scripts
│       ├── static/           # Static web resources
│       ├── templates/        # Thymeleaf templates
│       └── application.properties
└── test/
    ├── java/                 # Test classes
    └── resources/            # Test resources
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

1. Install Java 17+ and Maven 3.6+
2. Set up MariaDB locally
3. Configure email settings for testing
4. Run tests to ensure everything works: `mvn test`

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

For support and questions:

1. Check the [Issues](../../issues) page for existing problems
2. Create a new issue with detailed information
3. Include logs and configuration (without sensitive data)

## 📈 Roadmap

- [ ] Multi-factor authentication (MFA)
- [ ] OAuth2/OpenID Connect integration
- [ ] Advanced session management
- [ ] Enhanced audit logging
- [ ] API rate limiting improvements
- [ ] Mobile app support

---

**Built with ❤️ using Spring Boot and modern security practices**