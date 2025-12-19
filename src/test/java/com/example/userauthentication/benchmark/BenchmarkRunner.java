package com.example.userauthentication.benchmark;

import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;

/**
 * Utility class to run JMH benchmarks and analyze performance results.
 * 
 * **Feature: user-authentication, Benchmark execution and performance analysis**
 * 
 * Requirements: 2.1 (performance monitoring), 2.5 (load testing), 5.4 (performance thresholds)
 */
public class BenchmarkRunner {

    private static final Logger logger = LoggerFactory.getLogger(BenchmarkRunner.class);
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");

    /**
     * Run all authentication benchmarks and analyze results.
     */
    public static void runAllBenchmarks() throws RunnerException {
        logger.info("Starting authentication performance benchmarks...");
        
        Options options = new OptionsBuilder()
                .include(AuthenticationBenchmark.class.getSimpleName())
                .include(ConcurrentAuthenticationBenchmark.class.getSimpleName())
                .shouldDoGC(true)
                .shouldFailOnError(true)
                .jvmArgs("-server")
                .build();

        Runner runner = new Runner(options);
        Collection<RunResult> results = runner.run();
        
        analyzeResults(results);
        generatePerformanceReport(results);
        
        logger.info("Authentication performance benchmarks completed.");
    }

    /**
     * Run only single-threaded benchmarks.
     */
    public static void runSingleThreadedBenchmarks() throws RunnerException {
        logger.info("Starting single-threaded authentication benchmarks...");
        
        Options options = new OptionsBuilder()
                .include(AuthenticationBenchmark.class.getSimpleName())
                .shouldDoGC(true)
                .shouldFailOnError(true)
                .jvmArgs("-server")
                .build();

        Runner runner = new Runner(options);
        Collection<RunResult> results = runner.run();
        
        analyzeResults(results);
        
        logger.info("Single-threaded authentication benchmarks completed.");
    }

    /**
     * Run only concurrent benchmarks.
     */
    public static void runConcurrentBenchmarks() throws RunnerException {
        logger.info("Starting concurrent authentication benchmarks...");
        
        Options options = new OptionsBuilder()
                .include(ConcurrentAuthenticationBenchmark.class.getSimpleName())
                .shouldDoGC(true)
                .shouldFailOnError(true)
                .jvmArgs("-server")
                .build();

        Runner runner = new Runner(options);
        Collection<RunResult> results = runner.run();
        
        analyzeResults(results);
        
        logger.info("Concurrent authentication benchmarks completed.");
    }

    /**
     * Analyze benchmark results against performance thresholds.
     */
    private static void analyzeResults(Collection<RunResult> results) {
        logger.info("Analyzing benchmark results against performance thresholds...");
        
        boolean allThresholdsMet = true;
        
        for (RunResult result : results) {
            String benchmarkName = result.getParams().getBenchmark();
            String metricName = extractMetricName(benchmarkName);
            
            double primaryResult = result.getPrimaryResult().getScore();
            double threshold = PerformanceThresholds.getThreshold(metricName);
            
            boolean exceedsThreshold = PerformanceThresholds.exceedsThreshold(metricName, primaryResult);
            
            if (exceedsThreshold) {
                allThresholdsMet = false;
                String alertMessage = PerformanceThresholds.getAlertMessage(metricName, primaryResult, threshold);
                logger.warn(alertMessage);
            } else {
                logger.info("✓ {} performance within threshold: {:.2f} (threshold: {:.2f})", 
                           metricName, primaryResult, threshold);
            }
        }
        
        if (allThresholdsMet) {
            logger.info("✓ All performance benchmarks passed their thresholds!");
        } else {
            logger.warn("⚠ Some performance benchmarks exceeded their thresholds. Review the alerts above.");
        }
    }

    /**
     * Generate a detailed performance report.
     */
    private static void generatePerformanceReport(Collection<RunResult> results) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String reportFileName = "target/performance-report-" + timestamp + ".txt";
        
        try (FileWriter writer = new FileWriter(reportFileName)) {
            writer.write("Authentication Performance Benchmark Report\n");
            writer.write("==========================================\n\n");
            writer.write("Generated: " + LocalDateTime.now() + "\n\n");
            
            writer.write("Performance Thresholds:\n");
            writer.write("-----------------------\n");
            writeThresholdInfo(writer);
            writer.write("\n");
            
            writer.write("Benchmark Results:\n");
            writer.write("------------------\n");
            
            for (RunResult result : results) {
                String benchmarkName = result.getParams().getBenchmark();
                String metricName = extractMetricName(benchmarkName);
                
                writer.write(String.format("Benchmark: %s\n", benchmarkName));
                writer.write(String.format("Metric: %s\n", metricName));
                writer.write(String.format("Score: %.2f %s\n", 
                    result.getPrimaryResult().getScore(),
                    result.getPrimaryResult().getScoreUnit()));
                writer.write(String.format("Error: ±%.2f %s\n", 
                    result.getPrimaryResult().getScoreError(),
                    result.getPrimaryResult().getScoreUnit()));
                
                double threshold = PerformanceThresholds.getThreshold(metricName);
                boolean exceedsThreshold = PerformanceThresholds.exceedsThreshold(metricName, 
                    result.getPrimaryResult().getScore());
                
                writer.write(String.format("Threshold: %.2f\n", threshold));
                writer.write(String.format("Status: %s\n", exceedsThreshold ? "⚠ EXCEEDED" : "✓ PASSED"));
                writer.write("\n");
            }
            
            logger.info("Performance report generated: {}", reportFileName);
            
        } catch (IOException e) {
            logger.error("Failed to generate performance report: {}", e.getMessage());
        }
    }

    /**
     * Write threshold information to the report.
     */
    private static void writeThresholdInfo(FileWriter writer) throws IOException {
        writer.write("JWT Token Generation: " + PerformanceThresholds.JWT_TOKEN_GENERATION_THRESHOLD_US + " μs\n");
        writer.write("JWT Token Validation: " + PerformanceThresholds.JWT_TOKEN_VALIDATION_THRESHOLD_US + " μs\n");
        writer.write("Password Hashing: " + PerformanceThresholds.PASSWORD_HASHING_THRESHOLD_US + " μs\n");
        writer.write("Password Verification: " + PerformanceThresholds.PASSWORD_VERIFICATION_THRESHOLD_US + " μs\n");
        writer.write("Rate Limiting Check: " + PerformanceThresholds.RATE_LIMITING_CHECK_THRESHOLD_US + " μs\n");
        writer.write("Token Blacklisting: " + PerformanceThresholds.TOKEN_BLACKLISTING_THRESHOLD_US + " μs\n");
        writer.write("Blacklist Check: " + PerformanceThresholds.BLACKLIST_CHECK_THRESHOLD_US + " μs\n");
        writer.write("Concurrent JWT Generation: " + PerformanceThresholds.CONCURRENT_JWT_GENERATION_THRESHOLD_OPS + " ops/s\n");
        writer.write("Concurrent JWT Validation: " + PerformanceThresholds.CONCURRENT_JWT_VALIDATION_THRESHOLD_OPS + " ops/s\n");
        writer.write("Concurrent Password Verification: " + PerformanceThresholds.CONCURRENT_PASSWORD_VERIFICATION_THRESHOLD_OPS + " ops/s\n");
        writer.write("Concurrent Rate Limiting: " + PerformanceThresholds.CONCURRENT_RATE_LIMITING_THRESHOLD_OPS + " ops/s\n");
    }

    /**
     * Extract metric name from benchmark class and method name.
     */
    private static String extractMetricName(String benchmarkName) {
        if (benchmarkName.contains("benchmarkJwtTokenGeneration")) {
            return benchmarkName.contains("Concurrent") ? "concurrent_jwt_generation" : "jwt_token_generation";
        } else if (benchmarkName.contains("benchmarkJwtTokenValidation")) {
            return benchmarkName.contains("Concurrent") ? "concurrent_jwt_validation" : "jwt_token_validation";
        } else if (benchmarkName.contains("benchmarkPasswordHashing")) {
            return "password_hashing";
        } else if (benchmarkName.contains("benchmarkPasswordVerification")) {
            return benchmarkName.contains("Concurrent") ? "concurrent_password_verification" : "password_verification";
        } else if (benchmarkName.contains("benchmarkRateLimitingCheck")) {
            return benchmarkName.contains("Concurrent") ? "concurrent_rate_limiting" : "rate_limiting_check";
        } else if (benchmarkName.contains("benchmarkRefreshTokenGeneration")) {
            return "jwt_refresh_token_generation";
        } else if (benchmarkName.contains("benchmarkTokenBlacklisting")) {
            return benchmarkName.contains("Concurrent") ? "concurrent_token_blacklisting" : "token_blacklisting";
        } else if (benchmarkName.contains("benchmarkBlacklistCheck")) {
            return "blacklist_check";
        } else if (benchmarkName.contains("benchmarkMixedAuthenticationOperations")) {
            return "concurrent_mixed_operations";
        }
        return "unknown_metric";
    }

    /**
     * Main method to run benchmarks from command line.
     */
    public static void main(String[] args) {
        try {
            if (args.length > 0) {
                switch (args[0].toLowerCase()) {
                    case "single" -> runSingleThreadedBenchmarks();
                    case "concurrent" -> runConcurrentBenchmarks();
                    case "all" -> runAllBenchmarks();
                    default -> {
                        System.out.println("Usage: java BenchmarkRunner [single|concurrent|all]");
                        System.exit(1);
                    }
                }
            } else {
                runAllBenchmarks();
            }
        } catch (RunnerException e) {
            logger.error("Benchmark execution failed: {}", e.getMessage());
            System.exit(1);
        }
    }
}