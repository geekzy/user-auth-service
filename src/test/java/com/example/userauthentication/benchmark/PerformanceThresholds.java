package com.example.userauthentication.benchmark;

/**
 * Performance thresholds and alerts configuration for authentication operations.
 * 
 * **Feature: user-authentication, Performance thresholds and monitoring configuration**
 * 
 * Requirements: 2.1 (login performance thresholds), 2.5 (account locking performance), 5.4 (rate limiting performance)
 */
public class PerformanceThresholds {

    // JWT Token Operations (microseconds)
    public static final double JWT_TOKEN_GENERATION_THRESHOLD_US = 500.0;
    public static final double JWT_TOKEN_VALIDATION_THRESHOLD_US = 200.0;
    public static final double JWT_REFRESH_TOKEN_GENERATION_THRESHOLD_US = 500.0;
    
    // Password Operations (microseconds)
    public static final double PASSWORD_HASHING_THRESHOLD_US = 100_000.0; // 100ms for BCrypt
    public static final double PASSWORD_VERIFICATION_THRESHOLD_US = 100_000.0; // 100ms for BCrypt
    
    // Rate Limiting Operations (microseconds)
    public static final double RATE_LIMITING_CHECK_THRESHOLD_US = 100.0;
    
    // Token Management Operations (microseconds)
    public static final double TOKEN_BLACKLISTING_THRESHOLD_US = 50.0;
    public static final double BLACKLIST_CHECK_THRESHOLD_US = 10.0;
    
    // Concurrent Operations (operations per second)
    public static final double CONCURRENT_JWT_GENERATION_THRESHOLD_OPS = 10_000.0;
    public static final double CONCURRENT_JWT_VALIDATION_THRESHOLD_OPS = 50_000.0;
    public static final double CONCURRENT_PASSWORD_VERIFICATION_THRESHOLD_OPS = 100.0;
    public static final double CONCURRENT_RATE_LIMITING_THRESHOLD_OPS = 100_000.0;
    public static final double CONCURRENT_TOKEN_BLACKLISTING_THRESHOLD_OPS = 10_000.0;
    public static final double CONCURRENT_MIXED_OPERATIONS_THRESHOLD_OPS = 5_000.0;
    
    // Authentication Success Rate Thresholds (percentages)
    public static final double AUTHENTICATION_SUCCESS_RATE_THRESHOLD = 95.0;
    public static final double AUTHENTICATION_FAILURE_RATE_THRESHOLD = 5.0;
    
    // Response Time Thresholds (milliseconds)
    public static final double AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS = 500.0;
    public static final double MAX_AUTHENTICATION_TIME_THRESHOLD_MS = 2000.0;
    
    // Database Connection Pool Thresholds (percentages)
    public static final double CONNECTION_POOL_UTILIZATION_THRESHOLD = 80.0;
    
    // Memory and Resource Thresholds
    public static final double MEMORY_USAGE_THRESHOLD_MB = 512.0;
    public static final double CPU_USAGE_THRESHOLD_PERCENT = 70.0;
    
    /**
     * Check if a performance metric exceeds its threshold.
     */
    public static boolean exceedsThreshold(String metricName, double value) {
        return switch (metricName.toLowerCase()) {
            case "jwt_token_generation" -> value > JWT_TOKEN_GENERATION_THRESHOLD_US;
            case "jwt_token_validation" -> value > JWT_TOKEN_VALIDATION_THRESHOLD_US;
            case "jwt_refresh_token_generation" -> value > JWT_REFRESH_TOKEN_GENERATION_THRESHOLD_US;
            case "password_hashing" -> value > PASSWORD_HASHING_THRESHOLD_US;
            case "password_verification" -> value > PASSWORD_VERIFICATION_THRESHOLD_US;
            case "rate_limiting_check" -> value > RATE_LIMITING_CHECK_THRESHOLD_US;
            case "token_blacklisting" -> value > TOKEN_BLACKLISTING_THRESHOLD_US;
            case "blacklist_check" -> value > BLACKLIST_CHECK_THRESHOLD_US;
            case "concurrent_jwt_generation" -> value < CONCURRENT_JWT_GENERATION_THRESHOLD_OPS;
            case "concurrent_jwt_validation" -> value < CONCURRENT_JWT_VALIDATION_THRESHOLD_OPS;
            case "concurrent_password_verification" -> value < CONCURRENT_PASSWORD_VERIFICATION_THRESHOLD_OPS;
            case "concurrent_rate_limiting" -> value < CONCURRENT_RATE_LIMITING_THRESHOLD_OPS;
            case "concurrent_token_blacklisting" -> value < CONCURRENT_TOKEN_BLACKLISTING_THRESHOLD_OPS;
            case "concurrent_mixed_operations" -> value < CONCURRENT_MIXED_OPERATIONS_THRESHOLD_OPS;
            case "authentication_success_rate" -> value < AUTHENTICATION_SUCCESS_RATE_THRESHOLD;
            case "authentication_failure_rate" -> value > AUTHENTICATION_FAILURE_RATE_THRESHOLD;
            case "average_authentication_time" -> value > AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS;
            case "max_authentication_time" -> value > MAX_AUTHENTICATION_TIME_THRESHOLD_MS;
            case "connection_pool_utilization" -> value > CONNECTION_POOL_UTILIZATION_THRESHOLD;
            case "memory_usage" -> value > MEMORY_USAGE_THRESHOLD_MB;
            case "cpu_usage" -> value > CPU_USAGE_THRESHOLD_PERCENT;
            default -> false;
        };
    }
    
    /**
     * Get the threshold value for a specific metric.
     */
    public static double getThreshold(String metricName) {
        return switch (metricName.toLowerCase()) {
            case "jwt_token_generation" -> JWT_TOKEN_GENERATION_THRESHOLD_US;
            case "jwt_token_validation" -> JWT_TOKEN_VALIDATION_THRESHOLD_US;
            case "jwt_refresh_token_generation" -> JWT_REFRESH_TOKEN_GENERATION_THRESHOLD_US;
            case "password_hashing" -> PASSWORD_HASHING_THRESHOLD_US;
            case "password_verification" -> PASSWORD_VERIFICATION_THRESHOLD_US;
            case "rate_limiting_check" -> RATE_LIMITING_CHECK_THRESHOLD_US;
            case "token_blacklisting" -> TOKEN_BLACKLISTING_THRESHOLD_US;
            case "blacklist_check" -> BLACKLIST_CHECK_THRESHOLD_US;
            case "concurrent_jwt_generation" -> CONCURRENT_JWT_GENERATION_THRESHOLD_OPS;
            case "concurrent_jwt_validation" -> CONCURRENT_JWT_VALIDATION_THRESHOLD_OPS;
            case "concurrent_password_verification" -> CONCURRENT_PASSWORD_VERIFICATION_THRESHOLD_OPS;
            case "concurrent_rate_limiting" -> CONCURRENT_RATE_LIMITING_THRESHOLD_OPS;
            case "concurrent_token_blacklisting" -> CONCURRENT_TOKEN_BLACKLISTING_THRESHOLD_OPS;
            case "concurrent_mixed_operations" -> CONCURRENT_MIXED_OPERATIONS_THRESHOLD_OPS;
            case "authentication_success_rate" -> AUTHENTICATION_SUCCESS_RATE_THRESHOLD;
            case "authentication_failure_rate" -> AUTHENTICATION_FAILURE_RATE_THRESHOLD;
            case "average_authentication_time" -> AVERAGE_AUTHENTICATION_TIME_THRESHOLD_MS;
            case "max_authentication_time" -> MAX_AUTHENTICATION_TIME_THRESHOLD_MS;
            case "connection_pool_utilization" -> CONNECTION_POOL_UTILIZATION_THRESHOLD;
            case "memory_usage" -> MEMORY_USAGE_THRESHOLD_MB;
            case "cpu_usage" -> CPU_USAGE_THRESHOLD_PERCENT;
            default -> Double.MAX_VALUE;
        };
    }
    
    /**
     * Get performance alert message for threshold violations.
     */
    public static String getAlertMessage(String metricName, double value, double threshold) {
        String comparison = metricName.startsWith("concurrent_") ? "below" : "above";
        return String.format(
            "PERFORMANCE ALERT: %s is %s threshold. Current: %.2f, Threshold: %.2f",
            metricName, comparison, value, threshold
        );
    }
}