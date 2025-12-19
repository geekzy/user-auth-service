package com.example.userauthentication.benchmark;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive performance test suite for authentication operations.
 * Combines JMH benchmarks with load testing scenarios.
 * 
 * **Feature: user-authentication, Comprehensive performance test suite**
 * 
 * Requirements: 2.1 (login performance), 2.5 (account locking performance), 5.4 (rate limiting performance)
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class PerformanceTestSuite {

    private static final Logger logger = LoggerFactory.getLogger(PerformanceTestSuite.class);
    
    private LoadTestScenarios loadTestScenarios;

    @BeforeAll
    void setUp() {
        logger.info("Setting up performance test suite...");
        loadTestScenarios = new LoadTestScenarios();
    }

    @AfterAll
    void tearDown() {
        logger.info("Tearing down performance test suite...");
        if (loadTestScenarios != null) {
            loadTestScenarios.shutdown();
        }
    }

    /**
     * Test high-volume login performance.
     * Validates system can handle concurrent authentication requests.
     */
    @Test
    void testHighVolumeLoginPerformance() {
        logger.info("Testing high-volume login performance...");
        
        // Test with 50 concurrent users for 30 seconds
        LoadTestScenarios.LoadTestResult result = loadTestScenarios.simulateHighVolumeLogin(50, 30);
        
        // Validate performance metrics
        assertNotNull(result, "Load test result should not be null");
        assertTrue(result.getSuccessRate() >= PerformanceThresholds.AUTHENTICATION_SUCCESS_RATE_THRESHOLD,
                  "Authentication success rate should be >= " + PerformanceThresholds.AUTHENTICATION_SUCCESS_RATE_THRESHOLD + "%");
        assertTrue(result.getAverageResponseTime() <= PerformanceThresholds.AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS,
                  "Average response time should be <= " + PerformanceThresholds.AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS + "ms");
        assertTrue(result.getThroughput() > 0, "Throughput should be positive");
        
        logger.info("High-volume login performance test passed: {}", result);
    }

    /**
     * Test brute force attack resistance.
     * Validates rate limiting effectiveness under attack conditions.
     */
    @Test
    void testBruteForceAttackResistance() {
        logger.info("Testing brute force attack resistance...");
        
        // Test with 20 attackers for 15 seconds
        LoadTestScenarios.LoadTestResult result = loadTestScenarios.simulateBruteForceAttack(20, 15);
        
        // Validate rate limiting effectiveness
        assertNotNull(result, "Load test result should not be null");
        assertTrue(result.getFailureCount() > 0, "Rate limiting should block some requests");
        
        // Calculate block rate (failures are blocked requests in this context)
        double blockRate = (double) result.getFailureCount() / result.getTotalOperations() * 100.0;
        assertTrue(blockRate > 50.0, "Rate limiting should block at least 50% of brute force attempts");
        
        logger.info("Brute force attack resistance test passed: {} ({}% blocked)", result, blockRate);
    }

    /**
     * Test mixed workload performance.
     * Validates system performance under realistic usage patterns.
     */
    @Test
    void testMixedWorkloadPerformance() {
        logger.info("Testing mixed workload performance...");
        
        // Test with 30 users for 45 seconds
        LoadTestScenarios.LoadTestResult result = loadTestScenarios.simulateMixedWorkload(30, 45);
        
        // Validate mixed workload performance
        assertNotNull(result, "Load test result should not be null");
        assertTrue(result.getSuccessRate() >= 80.0, "Mixed workload success rate should be >= 80%");
        assertTrue(result.getAverageResponseTime() <= PerformanceThresholds.AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS * 1.5,
                  "Mixed workload average response time should be reasonable");
        assertTrue(result.getThroughput() > 0, "Throughput should be positive");
        
        logger.info("Mixed workload performance test passed: {}", result);
    }

    /**
     * Test performance under memory pressure.
     * Validates system behavior when memory usage is high.
     */
    @Test
    void testPerformanceUnderMemoryPressure() {
        logger.info("Testing performance under memory pressure...");
        
        // Create memory pressure by allocating large objects
        try {
            // Allocate memory to simulate pressure (but not cause OOM)
            byte[][] memoryPressure = new byte[100][1024 * 1024]; // 100MB
            
            // Run performance test under memory pressure
            LoadTestScenarios.LoadTestResult result = loadTestScenarios.simulateHighVolumeLogin(20, 20);
            
            // Validate performance doesn't degrade significantly
            assertNotNull(result, "Load test result should not be null");
            assertTrue(result.getSuccessRate() >= 90.0, "Success rate should remain high under memory pressure");
            assertTrue(result.getAverageResponseTime() <= PerformanceThresholds.AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS * 2,
                      "Response time should not degrade too much under memory pressure");
            
            // Clean up memory
            memoryPressure = null;
            System.gc();
            
            logger.info("Performance under memory pressure test passed: {}", result);
            
        } catch (OutOfMemoryError e) {
            logger.warn("Could not create sufficient memory pressure for test: {}", e.getMessage());
            // Skip this test if we can't create memory pressure
        }
    }

    /**
     * Test performance degradation thresholds.
     * Validates system fails gracefully when overloaded.
     */
    @Test
    void testPerformanceDegradationThresholds() {
        logger.info("Testing performance degradation thresholds...");
        
        // Test with increasing load to find degradation point
        int[] userCounts = {10, 25, 50, 75, 100};
        LoadTestScenarios.LoadTestResult previousResult = null;
        
        for (int userCount : userCounts) {
            LoadTestScenarios.LoadTestResult result = loadTestScenarios.simulateHighVolumeLogin(userCount, 15);
            
            assertNotNull(result, "Load test result should not be null");
            
            if (previousResult != null) {
                // Validate that throughput doesn't decrease dramatically
                double throughputRatio = result.getThroughput() / previousResult.getThroughput();
                assertTrue(throughputRatio > 0.5, 
                          "Throughput should not decrease by more than 50% when load increases");
                
                // Validate that response time doesn't increase dramatically
                double responseTimeRatio = result.getAverageResponseTime() / previousResult.getAverageResponseTime();
                assertTrue(responseTimeRatio < 3.0, 
                          "Response time should not increase by more than 3x when load increases");
            }
            
            previousResult = result;
            logger.info("Load test with {} users: {}", userCount, result);
        }
        
        logger.info("Performance degradation thresholds test passed");
    }

    /**
     * Test concurrent rate limiting effectiveness.
     * Validates rate limiting works correctly under concurrent access.
     */
    @Test
    void testConcurrentRateLimitingEffectiveness() {
        logger.info("Testing concurrent rate limiting effectiveness...");
        
        // Test rate limiting with multiple concurrent attackers targeting same resource
        LoadTestScenarios.LoadTestResult result = loadTestScenarios.simulateBruteForceAttack(10, 10);
        
        // Validate rate limiting is effective
        assertNotNull(result, "Load test result should not be null");
        assertTrue(result.getTotalOperations() > 0, "Should have processed some operations");
        
        // In a brute force scenario, we expect many requests to be blocked
        double blockRate = (double) result.getFailureCount() / result.getTotalOperations() * 100.0;
        assertTrue(blockRate > 30.0, "Rate limiting should block at least 30% of concurrent attacks");
        
        logger.info("Concurrent rate limiting effectiveness test passed: {} ({}% blocked)", result, blockRate);
    }

    /**
     * Test system recovery after load.
     * Validates system returns to normal performance after high load.
     */
    @Test
    void testSystemRecoveryAfterLoad() {
        logger.info("Testing system recovery after load...");
        
        // First, create high load
        LoadTestScenarios.LoadTestResult highLoadResult = loadTestScenarios.simulateHighVolumeLogin(100, 20);
        assertNotNull(highLoadResult, "High load test result should not be null");
        
        // Wait for system to recover
        try {
            Thread.sleep(5000); // 5 second recovery period
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        // Test normal load after recovery
        LoadTestScenarios.LoadTestResult recoveryResult = loadTestScenarios.simulateHighVolumeLogin(20, 15);
        assertNotNull(recoveryResult, "Recovery test result should not be null");
        
        // Validate system has recovered
        assertTrue(recoveryResult.getSuccessRate() >= PerformanceThresholds.AUTHENTICATION_SUCCESS_RATE_THRESHOLD,
                  "Success rate should recover after load");
        assertTrue(recoveryResult.getAverageResponseTime() <= PerformanceThresholds.AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS,
                  "Response time should recover after load");
        
        logger.info("System recovery test passed. High load: {}, Recovery: {}", highLoadResult, recoveryResult);
    }
}