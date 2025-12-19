package com.example.userauthentication.benchmark;

import com.example.userauthentication.config.SecurityProperties;
import com.example.userauthentication.security.JwtTokenService;
import com.example.userauthentication.security.RateLimitingService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Load testing scenarios for authentication operations.
 * Tests system behavior under various load conditions.
 * 
 * **Feature: user-authentication, Load testing scenarios for authentication operations**
 * 
 * Requirements: 2.1 (concurrent login performance), 2.5 (account locking under load), 5.4 (rate limiting under load)
 */
public class LoadTestScenarios {

    private static final Logger logger = LoggerFactory.getLogger(LoadTestScenarios.class);
    
    private final JwtTokenService jwtTokenService;
    private final RateLimitingService rateLimitingService;
    private final BCryptPasswordEncoder passwordEncoder;
    private final ExecutorService executorService;

    public LoadTestScenarios() {
        // Initialize security properties
        SecurityProperties securityProperties = new SecurityProperties();
        SecurityProperties.Jwt jwtProperties = new SecurityProperties.Jwt();
        jwtProperties.setSecret("mySecretKeyForJWTTokenGenerationThatIsLongEnoughForHS512Algorithm");
        jwtProperties.setExpiration(3600000L); // 1 hour
        securityProperties.setJwt(jwtProperties);
        
        SecurityProperties.RateLimit rateLimitProperties = new SecurityProperties.RateLimit();
        rateLimitProperties.setMaxAttempts(10);
        rateLimitProperties.setWindowMinutes(15);
        securityProperties.setRateLimit(rateLimitProperties);
        
        // Initialize services
        this.jwtTokenService = new JwtTokenService(securityProperties);
        
        CacheManager cacheManager = new ConcurrentMapCacheManager("rateLimitCache");
        this.rateLimitingService = new RateLimitingService(securityProperties, cacheManager);
        
        this.passwordEncoder = new BCryptPasswordEncoder(10); // Lower cost for load testing
        
        // Create thread pool for load testing
        this.executorService = Executors.newFixedThreadPool(20);
    }

    /**
     * Simulate high-volume login scenario.
     * Tests concurrent authentication under normal load.
     */
    public LoadTestResult simulateHighVolumeLogin(int numberOfUsers, int durationSeconds) {
        logger.info("Starting high-volume login simulation: {} users for {} seconds", numberOfUsers, durationSeconds);
        
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);
        AtomicLong totalResponseTime = new AtomicLong(0);
        
        List<Future<Void>> futures = new ArrayList<>();
        Instant startTime = Instant.now();
        Instant endTime = startTime.plusSeconds(durationSeconds);
        
        for (int i = 0; i < numberOfUsers; i++) {
            final int userId = i;
            Future<Void> future = executorService.submit(() -> {
                while (Instant.now().isBefore(endTime)) {
                    Instant operationStart = Instant.now();
                    
                    try {
                        // Simulate login process
                        String email = "user" + userId + "@example.com";
                        String password = "TestPassword" + userId + "!";
                        String passwordHash = passwordEncoder.encode(password);
                        
                        // Verify password (simulating login)
                        boolean matches = passwordEncoder.matches(password, passwordHash);
                        
                        if (matches) {
                            // Generate JWT token
                            String token = jwtTokenService.generateToken((long) userId, email);
                            
                            // Validate token (simulating subsequent requests)
                            JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(token);
                            
                            if (tokenInfo != null) {
                                successCount.incrementAndGet();
                            } else {
                                failureCount.incrementAndGet();
                            }
                        } else {
                            failureCount.incrementAndGet();
                        }
                        
                        Duration operationDuration = Duration.between(operationStart, Instant.now());
                        totalResponseTime.addAndGet(operationDuration.toMillis());
                        
                        // Small delay to simulate realistic usage
                        Thread.sleep(ThreadLocalRandom.current().nextInt(10, 100));
                        
                    } catch (Exception e) {
                        failureCount.incrementAndGet();
                        logger.debug("Login simulation error for user {}: {}", userId, e.getMessage());
                    }
                }
                return null;
            });
            futures.add(future);
        }
        
        // Wait for all tasks to complete
        for (Future<Void> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                logger.error("Load test task failed: {}", e.getMessage());
            }
        }
        
        Duration actualDuration = Duration.between(startTime, Instant.now());
        int totalOperations = successCount.get() + failureCount.get();
        double averageResponseTime = totalOperations > 0 ? (double) totalResponseTime.get() / totalOperations : 0;
        double throughput = totalOperations / (double) actualDuration.getSeconds();
        
        LoadTestResult result = new LoadTestResult(
            "High Volume Login",
            numberOfUsers,
            actualDuration,
            successCount.get(),
            failureCount.get(),
            averageResponseTime,
            throughput
        );
        
        logger.info("High-volume login simulation completed: {}", result);
        return result;
    }

    /**
     * Simulate brute force attack scenario.
     * Tests rate limiting effectiveness under attack conditions.
     */
    public LoadTestResult simulateBruteForceAttack(int numberOfAttackers, int durationSeconds) {
        logger.info("Starting brute force attack simulation: {} attackers for {} seconds", numberOfAttackers, durationSeconds);
        
        AtomicInteger allowedCount = new AtomicInteger(0);
        AtomicInteger blockedCount = new AtomicInteger(0);
        AtomicLong totalResponseTime = new AtomicLong(0);
        
        List<Future<Void>> futures = new ArrayList<>();
        Instant startTime = Instant.now();
        Instant endTime = startTime.plusSeconds(durationSeconds);
        
        for (int i = 0; i < numberOfAttackers; i++) {
            final int attackerId = i;
            Future<Void> future = executorService.submit(() -> {
                String attackerKey = "attacker_" + attackerId;
                
                while (Instant.now().isBefore(endTime)) {
                    Instant operationStart = Instant.now();
                    
                    try {
                        // Check rate limiting
                        boolean allowed = rateLimitingService.isAllowed(attackerKey);
                        
                        if (allowed) {
                            allowedCount.incrementAndGet();
                            
                            // Simulate failed login attempt
                            String password = "WrongPassword" + System.nanoTime();
                            String correctHash = passwordEncoder.encode("CorrectPassword");
                            passwordEncoder.matches(password, correctHash); // This will fail
                            
                        } else {
                            blockedCount.incrementAndGet();
                        }
                        
                        Duration operationDuration = Duration.between(operationStart, Instant.now());
                        totalResponseTime.addAndGet(operationDuration.toMillis());
                        
                        // Aggressive attack - minimal delay
                        Thread.sleep(ThreadLocalRandom.current().nextInt(1, 10));
                        
                    } catch (Exception e) {
                        logger.debug("Brute force simulation error for attacker {}: {}", attackerId, e.getMessage());
                    }
                }
                return null;
            });
            futures.add(future);
        }
        
        // Wait for all tasks to complete
        for (Future<Void> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                logger.error("Brute force test task failed: {}", e.getMessage());
            }
        }
        
        Duration actualDuration = Duration.between(startTime, Instant.now());
        int totalOperations = allowedCount.get() + blockedCount.get();
        double averageResponseTime = totalOperations > 0 ? (double) totalResponseTime.get() / totalOperations : 0;
        double throughput = totalOperations / (double) actualDuration.getSeconds();
        
        LoadTestResult result = new LoadTestResult(
            "Brute Force Attack",
            numberOfAttackers,
            actualDuration,
            allowedCount.get(),
            blockedCount.get(),
            averageResponseTime,
            throughput
        );
        
        logger.info("Brute force attack simulation completed: {}", result);
        return result;
    }

    /**
     * Simulate mixed authentication workload.
     * Tests realistic mix of authentication operations under load.
     */
    public LoadTestResult simulateMixedWorkload(int numberOfUsers, int durationSeconds) {
        logger.info("Starting mixed workload simulation: {} users for {} seconds", numberOfUsers, durationSeconds);
        
        AtomicInteger successCount = new AtomicInteger(0);
        AtomicInteger failureCount = new AtomicInteger(0);
        AtomicLong totalResponseTime = new AtomicLong(0);
        
        List<Future<Void>> futures = new ArrayList<>();
        Instant startTime = Instant.now();
        Instant endTime = startTime.plusSeconds(durationSeconds);
        
        for (int i = 0; i < numberOfUsers; i++) {
            final int userId = i;
            Future<Void> future = executorService.submit(() -> {
                String email = "user" + userId + "@example.com";
                String token = null;
                boolean isLoggedIn = false;
                
                // Start each user with a login to establish initial state
                try {
                    String password = "TestPassword" + userId + "!";
                    String passwordHash = passwordEncoder.encode(password);
                    boolean matches = passwordEncoder.matches(password, passwordHash);
                    
                    if (matches) {
                        token = jwtTokenService.generateToken((long) userId, email);
                        isLoggedIn = true;
                    }
                } catch (Exception e) {
                    logger.debug("Initial login failed for user {}: {}", userId, e.getMessage());
                }
                
                while (Instant.now().isBefore(endTime)) {
                    Instant operationStart = Instant.now();
                    
                    try {
                        // Adjust operation selection based on login state
                        int operation;
                        if (!isLoggedIn) {
                            // If not logged in, force login operation
                            operation = 0;
                        } else {
                            // If logged in, choose from all operations with weighted distribution
                            int rand = ThreadLocalRandom.current().nextInt(100);
                            if (rand < 15) {
                                operation = 0; // Login (15% - re-login)
                            } else if (rand < 55) {
                                operation = 1; // Token validation (40%)
                            } else if (rand < 75) {
                                operation = 2; // Rate limiting check (20%)
                            } else if (rand < 90) {
                                operation = 3; // Token refresh (15%)
                            } else {
                                operation = 4; // Logout (10%)
                            }
                        }
                        
                        switch (operation) {
                            case 0: // Login
                                String password = "TestPassword" + userId + "!";
                                String passwordHash = passwordEncoder.encode(password);
                                boolean matches = passwordEncoder.matches(password, passwordHash);
                                
                                if (matches) {
                                    token = jwtTokenService.generateToken((long) userId, email);
                                    isLoggedIn = true;
                                    successCount.incrementAndGet();
                                } else {
                                    failureCount.incrementAndGet();
                                }
                                break;
                                
                            case 1: // Token validation
                                if (token != null && isLoggedIn) {
                                    JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(token);
                                    if (tokenInfo != null) {
                                        successCount.incrementAndGet();
                                    } else {
                                        // Token might be expired or invalid, mark as not logged in
                                        isLoggedIn = false;
                                        token = null;
                                        failureCount.incrementAndGet();
                                    }
                                } else {
                                    failureCount.incrementAndGet();
                                }
                                break;
                                
                            case 2: // Rate limiting check
                                String rateLimitKey = "user_" + userId;
                                boolean allowed = rateLimitingService.isAllowed(rateLimitKey);
                                if (allowed) {
                                    successCount.incrementAndGet();
                                } else {
                                    failureCount.incrementAndGet();
                                }
                                break;
                                
                            case 3: // Token refresh
                                if (token != null && isLoggedIn) {
                                    String refreshToken = jwtTokenService.generateRefreshToken((long) userId, email);
                                    String newToken = jwtTokenService.refreshAccessToken(refreshToken);
                                    if (newToken != null) {
                                        token = newToken;
                                        successCount.incrementAndGet();
                                    } else {
                                        failureCount.incrementAndGet();
                                    }
                                } else {
                                    failureCount.incrementAndGet();
                                }
                                break;
                                
                            case 4: // Logout
                                if (token != null && isLoggedIn) {
                                    jwtTokenService.blacklistToken(token);
                                    token = null;
                                    isLoggedIn = false;
                                    successCount.incrementAndGet();
                                } else {
                                    failureCount.incrementAndGet();
                                }
                                break;
                        }
                        
                        Duration operationDuration = Duration.between(operationStart, Instant.now());
                        totalResponseTime.addAndGet(operationDuration.toMillis());
                        
                        // Realistic delay between operations
                        Thread.sleep(ThreadLocalRandom.current().nextInt(50, 200));
                        
                    } catch (Exception e) {
                        failureCount.incrementAndGet();
                        logger.debug("Mixed workload simulation error for user {}: {}", userId, e.getMessage());
                    }
                }
                return null;
            });
            futures.add(future);
        }
        
        // Wait for all tasks to complete
        for (Future<Void> future : futures) {
            try {
                future.get();
            } catch (Exception e) {
                logger.error("Mixed workload test task failed: {}", e.getMessage());
            }
        }
        
        Duration actualDuration = Duration.between(startTime, Instant.now());
        int totalOperations = successCount.get() + failureCount.get();
        double averageResponseTime = totalOperations > 0 ? (double) totalResponseTime.get() / totalOperations : 0;
        double throughput = totalOperations / (double) actualDuration.getSeconds();
        
        LoadTestResult result = new LoadTestResult(
            "Mixed Workload",
            numberOfUsers,
            actualDuration,
            successCount.get(),
            failureCount.get(),
            averageResponseTime,
            throughput
        );
        
        logger.info("Mixed workload simulation completed: {}", result);
        return result;
    }

    /**
     * Shutdown the executor service.
     */
    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(60, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Load test result data class.
     */
    public static class LoadTestResult {
        private final String scenarioName;
        private final int numberOfUsers;
        private final Duration duration;
        private final int successCount;
        private final int failureCount;
        private final double averageResponseTime;
        private final double throughput;

        public LoadTestResult(String scenarioName, int numberOfUsers, Duration duration,
                            int successCount, int failureCount, double averageResponseTime, double throughput) {
            this.scenarioName = scenarioName;
            this.numberOfUsers = numberOfUsers;
            this.duration = duration;
            this.successCount = successCount;
            this.failureCount = failureCount;
            this.averageResponseTime = averageResponseTime;
            this.throughput = throughput;
        }

        // Getters
        public String getScenarioName() { return scenarioName; }
        public int getNumberOfUsers() { return numberOfUsers; }
        public Duration getDuration() { return duration; }
        public int getSuccessCount() { return successCount; }
        public int getFailureCount() { return failureCount; }
        public double getAverageResponseTime() { return averageResponseTime; }
        public double getThroughput() { return throughput; }
        public int getTotalOperations() { return successCount + failureCount; }
        public double getSuccessRate() { 
            int total = getTotalOperations();
            return total > 0 ? (double) successCount / total * 100.0 : 0.0;
        }

        @Override
        public String toString() {
            return String.format(
                "%s: %d users, %.1fs duration, %d operations (%.1f%% success), %.2fms avg response, %.1f ops/s",
                scenarioName, numberOfUsers, duration.toMillis() / 1000.0, getTotalOperations(),
                getSuccessRate(), averageResponseTime, throughput
            );
        }
    }
}