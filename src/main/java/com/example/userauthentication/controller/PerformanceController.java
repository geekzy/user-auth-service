package com.example.userauthentication.controller;

import com.example.userauthentication.service.PerformanceMonitoringService;
import io.micrometer.core.annotation.Timed;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for exposing performance metrics and health information.
 * Provides endpoints for monitoring dashboards and health checks.
 */
@RestController
@RequestMapping("/api/performance")
public class PerformanceController {

    private final PerformanceMonitoringService performanceMonitoringService;

    public PerformanceController(PerformanceMonitoringService performanceMonitoringService) {
        this.performanceMonitoringService = performanceMonitoringService;
    }

    /**
     * Get comprehensive performance summary.
     */
    @GetMapping("/summary")
    @Timed(value = "auth.performance.summary.time", description = "Time taken to generate performance summary")
    public ResponseEntity<PerformanceMonitoringService.PerformanceSummary> getPerformanceSummary() {
        PerformanceMonitoringService.PerformanceSummary summary = 
            performanceMonitoringService.getPerformanceSummary();
        return ResponseEntity.ok(summary);
    }

    /**
     * Get authentication success rate.
     */
    @GetMapping("/auth-success-rate")
    @Timed(value = "auth.performance.success.rate.time", description = "Time taken to calculate success rate")
    public ResponseEntity<Double> getAuthenticationSuccessRate() {
        double successRate = performanceMonitoringService.getAuthenticationSuccessRate();
        return ResponseEntity.ok(successRate);
    }

    /**
     * Get authentication failure rate.
     */
    @GetMapping("/auth-failure-rate")
    @Timed(value = "auth.performance.failure.rate.time", description = "Time taken to calculate failure rate")
    public ResponseEntity<Double> getAuthenticationFailureRate() {
        double failureRate = performanceMonitoringService.getAuthenticationFailureRate();
        return ResponseEntity.ok(failureRate);
    }

    /**
     * Get average authentication time.
     */
    @GetMapping("/avg-auth-time")
    @Timed(value = "auth.performance.avg.time.calculation", description = "Time taken to calculate average auth time")
    public ResponseEntity<Double> getAverageAuthenticationTime() {
        double avgTime = performanceMonitoringService.getAverageAuthenticationTime();
        return ResponseEntity.ok(avgTime);
    }

    /**
     * Get database connection pool utilization.
     */
    @GetMapping("/db-pool-utilization")
    @Timed(value = "auth.performance.db.pool.check.time", description = "Time taken to check DB pool utilization")
    public ResponseEntity<Double> getConnectionPoolUtilization() {
        double utilization = performanceMonitoringService.getConnectionPoolUtilization();
        return ResponseEntity.ok(utilization);
    }

    /**
     * Get performance health status.
     */
    @GetMapping("/health")
    @Timed(value = "auth.performance.health.check.time", description = "Time taken to perform health check")
    public ResponseEntity<HealthStatus> getPerformanceHealth() {
        boolean healthy = performanceMonitoringService.isPerformanceHealthy();
        PerformanceMonitoringService.PerformanceSummary summary = 
            performanceMonitoringService.getPerformanceSummary();
        
        return ResponseEntity.ok(new HealthStatus(healthy, summary));
    }

    /**
     * Health status response class.
     */
    public static class HealthStatus {
        private final boolean healthy;
        private final PerformanceMonitoringService.PerformanceSummary summary;

        public HealthStatus(boolean healthy, PerformanceMonitoringService.PerformanceSummary summary) {
            this.healthy = healthy;
            this.summary = summary;
        }

        public boolean isHealthy() { return healthy; }
        public PerformanceMonitoringService.PerformanceSummary getSummary() { return summary; }
    }
}