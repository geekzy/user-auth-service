package com.example.userauthentication.service;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service for advanced performance monitoring and alerting.
 * Provides additional monitoring capabilities beyond basic metrics.
 */
@Service
@ConfigurationProperties(prefix = "app.performance.monitoring")
public class PerformanceMonitoringService {

    private static final Logger logger = LoggerFactory.getLogger(PerformanceMonitoringService.class);
    
    private final MeterRegistry meterRegistry;
    private final DataSource dataSource;
    
    // Configuration properties
    private boolean enabled = true;
    private boolean logSlowOperations = true;
    private long slowOperationThresholdMs = 1000;
    
    // Performance counters
    private final AtomicLong slowOperationCount = new AtomicLong(0);
    private final AtomicLong totalOperationCount = new AtomicLong(0);

    public PerformanceMonitoringService(MeterRegistry meterRegistry, DataSource dataSource) {
        this.meterRegistry = meterRegistry;
        this.dataSource = dataSource;
        
        // Register custom gauges
        meterRegistry.gauge("auth.performance.slow.operations", slowOperationCount);
        meterRegistry.gauge("auth.performance.total.operations", totalOperationCount);
    }

    /**
     * Record operation performance and check for slow operations.
     */
    public void recordOperationPerformance(String operationName, Duration duration) {
        if (!enabled) {
            return;
        }
        
        totalOperationCount.incrementAndGet();
        
        long durationMs = duration.toMillis();
        
        // Record timing metric
        Timer.builder("auth.operation.performance")
                .tag("operation", operationName)
                .register(meterRegistry)
                .record(duration);
        
        // Check for slow operations
        if (durationMs > slowOperationThresholdMs) {
            slowOperationCount.incrementAndGet();
            
            if (logSlowOperations) {
                logger.warn("Slow operation detected: {} took {}ms (threshold: {}ms)", 
                           operationName, durationMs, slowOperationThresholdMs);
            }
        }
    }

    /**
     * Get authentication success rate as a percentage.
     */
    public double getAuthenticationSuccessRate() {
        double successCount = meterRegistry.counter("auth.success.rate").count();
        double failureCount = meterRegistry.counter("auth.failure.rate").count();
        double totalCount = successCount + failureCount;
        
        if (totalCount == 0) {
            return 0.0;
        }
        
        return (successCount / totalCount) * 100.0;
    }

    /**
     * Get authentication failure rate as a percentage.
     */
    public double getAuthenticationFailureRate() {
        double successCount = meterRegistry.counter("auth.success.rate").count();
        double failureCount = meterRegistry.counter("auth.failure.rate").count();
        double totalCount = successCount + failureCount;
        
        if (totalCount == 0) {
            return 0.0;
        }
        
        return (failureCount / totalCount) * 100.0;
    }

    /**
     * Get average response time for authentication operations.
     */
    public double getAverageAuthenticationTime() {
        Timer authTimer = meterRegistry.find("auth.operation.duration").timer();
        if (authTimer != null) {
            return authTimer.mean(java.util.concurrent.TimeUnit.MILLISECONDS);
        }
        return 0.0;
    }

    /**
     * Get database connection pool utilization percentage.
     */
    public double getConnectionPoolUtilization() {
        try {
            if (dataSource instanceof com.zaxxer.hikari.HikariDataSource hikariDataSource) {
                int activeConnections = hikariDataSource.getHikariPoolMXBean().getActiveConnections();
                int totalConnections = hikariDataSource.getHikariPoolMXBean().getTotalConnections();
                
                if (totalConnections > 0) {
                    return ((double) activeConnections / totalConnections) * 100.0;
                }
            }
        } catch (Exception e) {
            logger.debug("Could not get connection pool utilization: {}", e.getMessage());
        }
        return 0.0;
    }

    /**
     * Check if system performance is healthy.
     */
    public boolean isPerformanceHealthy() {
        // Check authentication success rate (should be > 90%)
        double successRate = getAuthenticationSuccessRate();
        if (successRate < 90.0 && meterRegistry.counter("auth.success.rate").count() > 10) {
            logger.warn("Low authentication success rate: {}%", successRate);
            return false;
        }
        
        // Check average response time (should be < 500ms)
        double avgTime = getAverageAuthenticationTime();
        if (avgTime > 500.0) {
            logger.warn("High average authentication time: {}ms", avgTime);
            return false;
        }
        
        // Check connection pool utilization (should be < 80%)
        double poolUtilization = getConnectionPoolUtilization();
        if (poolUtilization > 80.0) {
            logger.warn("High connection pool utilization: {}%", poolUtilization);
            return false;
        }
        
        return true;
    }

    /**
     * Get performance summary for monitoring dashboards.
     */
    public PerformanceSummary getPerformanceSummary() {
        return new PerformanceSummary(
            getAuthenticationSuccessRate(),
            getAuthenticationFailureRate(),
            getAverageAuthenticationTime(),
            getConnectionPoolUtilization(),
            slowOperationCount.get(),
            totalOperationCount.get(),
            isPerformanceHealthy()
        );
    }

    // Configuration property setters
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setLogSlowOperations(boolean logSlowOperations) {
        this.logSlowOperations = logSlowOperations;
    }

    public void setSlowOperationThresholdMs(long slowOperationThresholdMs) {
        this.slowOperationThresholdMs = slowOperationThresholdMs;
    }

    /**
     * Performance summary data class.
     */
    public static class PerformanceSummary {
        private final double authenticationSuccessRate;
        private final double authenticationFailureRate;
        private final double averageAuthenticationTime;
        private final double connectionPoolUtilization;
        private final long slowOperationCount;
        private final long totalOperationCount;
        private final boolean healthy;

        public PerformanceSummary(double authenticationSuccessRate, double authenticationFailureRate,
                                double averageAuthenticationTime, double connectionPoolUtilization,
                                long slowOperationCount, long totalOperationCount, boolean healthy) {
            this.authenticationSuccessRate = authenticationSuccessRate;
            this.authenticationFailureRate = authenticationFailureRate;
            this.averageAuthenticationTime = averageAuthenticationTime;
            this.connectionPoolUtilization = connectionPoolUtilization;
            this.slowOperationCount = slowOperationCount;
            this.totalOperationCount = totalOperationCount;
            this.healthy = healthy;
        }

        // Getters
        public double getAuthenticationSuccessRate() { return authenticationSuccessRate; }
        public double getAuthenticationFailureRate() { return authenticationFailureRate; }
        public double getAverageAuthenticationTime() { return averageAuthenticationTime; }
        public double getConnectionPoolUtilization() { return connectionPoolUtilization; }
        public long getSlowOperationCount() { return slowOperationCount; }
        public long getTotalOperationCount() { return totalOperationCount; }
        public boolean isHealthy() { return healthy; }
    }
}