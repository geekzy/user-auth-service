package com.example.userauthentication.config;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;

/**
 * Configuration for custom metrics and monitoring.
 * Provides beans for tracking authentication operations and performance.
 */
@Configuration
public class MetricsConfig {

    /**
     * Counter for successful user registrations.
     */
    @Bean
    public Counter userRegistrationSuccessCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.user.registration.success")
                .description("Number of successful user registrations")
                .register(meterRegistry);
    }

    /**
     * Counter for failed user registrations.
     */
    @Bean
    public Counter userRegistrationFailureCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.user.registration.failure")
                .description("Number of failed user registrations")
                .tag("reason", "validation")
                .register(meterRegistry);
    }

    /**
     * Counter for successful login attempts.
     */
    @Bean
    public Counter loginSuccessCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.login.success")
                .description("Number of successful login attempts")
                .register(meterRegistry);
    }

    /**
     * Counter for failed login attempts.
     */
    @Bean
    public Counter loginFailureCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.login.failure")
                .description("Number of failed login attempts")
                .tag("reason", "invalid_credentials")
                .register(meterRegistry);
    }

    /**
     * Counter for logout operations.
     */
    @Bean
    public Counter logoutCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.logout.total")
                .description("Number of logout operations")
                .register(meterRegistry);
    }

    /**
     * Counter for password reset requests.
     */
    @Bean
    public Counter passwordResetRequestCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.password.reset.request")
                .description("Number of password reset requests")
                .register(meterRegistry);
    }

    /**
     * Counter for successful password resets.
     */
    @Bean
    public Counter passwordResetSuccessCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.password.reset.success")
                .description("Number of successful password resets")
                .register(meterRegistry);
    }

    /**
     * Timer for authentication operations performance.
     */
    @Bean
    public Timer authenticationTimer(MeterRegistry meterRegistry) {
        return Timer.builder("auth.operation.duration")
                .description("Duration of authentication operations")
                .register(meterRegistry);
    }

    /**
     * Timer for password hashing operations.
     */
    @Bean
    public Timer passwordHashingTimer(MeterRegistry meterRegistry) {
        return Timer.builder("auth.password.hashing.duration")
                .description("Duration of password hashing operations")
                .register(meterRegistry);
    }

    /**
     * Counter for rate limiting violations.
     */
    @Bean
    public Counter rateLimitViolationCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.rate.limit.violation")
                .description("Number of rate limit violations")
                .register(meterRegistry);
    }

    /**
     * Counter for JWT token generation.
     */
    @Bean
    public Counter jwtTokenGenerationCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.jwt.token.generation")
                .description("Number of JWT tokens generated")
                .register(meterRegistry);
    }

    /**
     * Counter for JWT token validation attempts.
     */
    @Bean
    public Counter jwtTokenValidationCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.jwt.token.validation")
                .description("Number of JWT token validation attempts")
                .register(meterRegistry);
    }

    /**
     * Counter for session creation.
     */
    @Bean
    public Counter sessionCreationCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.session.creation")
                .description("Number of sessions created")
                .register(meterRegistry);
    }

    /**
     * Counter for session invalidation.
     */
    @Bean
    public Counter sessionInvalidationCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.session.invalidation")
                .description("Number of sessions invalidated")
                .register(meterRegistry);
    }

    /**
     * Timer for database operations.
     */
    @Bean
    public Timer databaseOperationTimer(MeterRegistry meterRegistry) {
        return Timer.builder("auth.database.operation.duration")
                .description("Duration of database operations")
                .register(meterRegistry);
    }

    /**
     * Counter for authentication success rate.
     */
    @Bean
    public Counter authenticationSuccessRateCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.success.rate")
                .description("Authentication success rate counter")
                .register(meterRegistry);
    }

    /**
     * Counter for authentication failure rate.
     */
    @Bean
    public Counter authenticationFailureRateCounter(MeterRegistry meterRegistry) {
        return Counter.builder("auth.failure.rate")
                .description("Authentication failure rate counter")
                .register(meterRegistry);
    }

    /**
     * Configure HikariCP connection pool metrics.
     */
    @Bean
    public Gauge hikariConnectionPoolActiveConnections(MeterRegistry meterRegistry, DataSource dataSource) {
        if (dataSource instanceof HikariDataSource hikariDataSource) {
            return Gauge.builder("hikaricp.connections.active", hikariDataSource, 
                    ds -> ds.getHikariPoolMXBean().getActiveConnections())
                    .description("Active connections in HikariCP pool")
                    .register(meterRegistry);
        }
        return null;
    }

    /**
     * Configure HikariCP connection pool idle connections metric.
     */
    @Bean
    public Gauge hikariConnectionPoolIdleConnections(MeterRegistry meterRegistry, DataSource dataSource) {
        if (dataSource instanceof HikariDataSource hikariDataSource) {
            return Gauge.builder("hikaricp.connections.idle", hikariDataSource,
                    ds -> ds.getHikariPoolMXBean().getIdleConnections())
                    .description("Idle connections in HikariCP pool")
                    .register(meterRegistry);
        }
        return null;
    }

    /**
     * Configure HikariCP connection pool total connections metric.
     */
    @Bean
    public Gauge hikariConnectionPoolTotalConnections(MeterRegistry meterRegistry, DataSource dataSource) {
        if (dataSource instanceof HikariDataSource hikariDataSource) {
            return Gauge.builder("hikaricp.connections.total", hikariDataSource,
                    ds -> ds.getHikariPoolMXBean().getTotalConnections())
                    .description("Total connections in HikariCP pool")
                    .register(meterRegistry);
        }
        return null;
    }

    /**
     * Configure HikariCP connection pool pending threads metric.
     */
    @Bean
    public Gauge hikariConnectionPoolPendingThreads(MeterRegistry meterRegistry, DataSource dataSource) {
        if (dataSource instanceof HikariDataSource hikariDataSource) {
            return Gauge.builder("hikaricp.connections.pending", hikariDataSource,
                    ds -> ds.getHikariPoolMXBean().getThreadsAwaitingConnection())
                    .description("Pending threads waiting for connections")
                    .register(meterRegistry);
        }
        return null;
    }
}