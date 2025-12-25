package com.example.userauthentication.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Service for periodic performance reporting and health checks.
 * Logs performance metrics at regular intervals for monitoring.
 */
@Service
@ConditionalOnProperty(name = "app.performance.monitoring.enabled", havingValue = "true", matchIfMissing = true)
public class PerformanceReportingService {

    private static final Logger logger = LoggerFactory.getLogger(PerformanceReportingService.class);
    
    private final PerformanceMonitoringService performanceMonitoringService;

    public PerformanceReportingService(PerformanceMonitoringService performanceMonitoringService) {
        this.performanceMonitoringService = performanceMonitoringService;
    }

    /**
     * Log performance summary every minute (for development POC).
     */
    @Scheduled(fixedRate = 60000) // 1 minute
    public void logPerformanceSummary() {
        try {
            PerformanceMonitoringService.PerformanceSummary summary = 
                performanceMonitoringService.getPerformanceSummary();
            
            logger.info(String.format("Performance Summary - " +
                       "Auth Success Rate: %.2f%%, " +
                       "Auth Failure Rate: %.2f%%, " +
                       "Avg Auth Time: %.2fms, " +
                       "DB Pool Utilization: %.2f%%, " +
                       "Slow Operations: %d/%d, " +
                       "Health Status: %s",
                       summary.getAuthenticationSuccessRate(),
                       summary.getAuthenticationFailureRate(),
                       summary.getAverageAuthenticationTime(),
                       summary.getConnectionPoolUtilization(),
                       summary.getSlowOperationCount(),
                       summary.getTotalOperationCount(),
                       summary.isHealthy() ? "HEALTHY" : "UNHEALTHY"));
            
            // Log warning if performance is not healthy
            if (!summary.isHealthy()) {
                logger.warn("Performance health check failed! System may be experiencing issues.");
            }
            
        } catch (Exception e) {
            logger.error("Error generating performance summary: {}", e.getMessage());
        }
    }

    /**
     * Perform detailed performance health check every minute (for development POC).
     */
    @Scheduled(fixedRate = 60000) // 1 minute
    public void performDetailedHealthCheck() {
        try {
            PerformanceMonitoringService.PerformanceSummary summary = 
                performanceMonitoringService.getPerformanceSummary();
            
            logger.info("=== Detailed Performance Health Check ===");
            logger.info(String.format("Authentication Success Rate: %.2f%%", summary.getAuthenticationSuccessRate()));
            logger.info(String.format("Authentication Failure Rate: %.2f%%", summary.getAuthenticationFailureRate()));
            logger.info(String.format("Average Authentication Time: %.2fms", summary.getAverageAuthenticationTime()));
            logger.info(String.format("Database Connection Pool Utilization: %.2f%%", summary.getConnectionPoolUtilization()));
            logger.info("Slow Operations Count: {}", summary.getSlowOperationCount());
            logger.info("Total Operations Count: {}", summary.getTotalOperationCount());
            logger.info("Overall Health Status: {}", summary.isHealthy() ? "HEALTHY" : "UNHEALTHY");
            logger.info("==========================================");
            
            // Additional checks and recommendations
            if (summary.getAuthenticationFailureRate() > 10.0) {
                logger.warn("High authentication failure rate detected. Consider investigating potential security issues or user experience problems.");
            }
            
            if (summary.getAverageAuthenticationTime() > 200.0) {
                logger.warn("Authentication operations are slower than optimal. Consider database optimization or caching improvements.");
            }
            
            if (summary.getConnectionPoolUtilization() > 70.0) {
                logger.warn("Database connection pool utilization is high. Consider increasing pool size or optimizing queries.");
            }
            
        } catch (Exception e) {
            logger.error("Error performing detailed health check: {}", e.getMessage());
        }
    }
}