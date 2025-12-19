package com.example.userauthentication;

import com.example.userauthentication.service.PerformanceMonitoringService;
import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for performance monitoring functionality.
 */
@SpringBootTest
@ActiveProfiles("test")
class PerformanceMonitoringTest {

    @Autowired
    private PerformanceMonitoringService performanceMonitoringService;

    @Autowired
    private MeterRegistry meterRegistry;

    @Test
    void testPerformanceMonitoringServiceExists() {
        assertNotNull(performanceMonitoringService);
        assertNotNull(meterRegistry);
    }

    @Test
    void testPerformanceSummaryGeneration() {
        PerformanceMonitoringService.PerformanceSummary summary = 
            performanceMonitoringService.getPerformanceSummary();
        
        assertNotNull(summary);
        assertTrue(summary.getAuthenticationSuccessRate() >= 0);
        assertTrue(summary.getAuthenticationFailureRate() >= 0);
        assertTrue(summary.getAverageAuthenticationTime() >= 0);
        assertTrue(summary.getConnectionPoolUtilization() >= 0);
        assertTrue(summary.getSlowOperationCount() >= 0);
        assertTrue(summary.getTotalOperationCount() >= 0);
    }

    @Test
    void testHealthCheckFunctionality() {
        boolean healthy = performanceMonitoringService.isPerformanceHealthy();
        // Should be healthy with no operations
        assertTrue(healthy);
    }

    @Test
    void testMetricsRegistration() {
        // Verify that custom metrics are registered
        assertNotNull(meterRegistry.find("auth.performance.slow.operations").gauge());
        assertNotNull(meterRegistry.find("auth.performance.total.operations").gauge());
    }
}