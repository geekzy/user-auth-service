package com.example.userauthentication.benchmark;

import com.example.userauthentication.config.SecurityProperties;
import com.example.userauthentication.security.JwtTokenService;
import com.example.userauthentication.security.RateLimitingService;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/**
 * JMH benchmarks for concurrent authentication scenarios.
 * Tests performance under load with multiple threads.
 * 
 * **Feature: user-authentication, Concurrent performance benchmarks for authentication operations**
 * 
 * Requirements: 2.1 (concurrent login performance), 2.5 (account locking under load), 5.4 (rate limiting under load)
 */
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
@Fork(value = 1, jvmArgs = {"-Xms2G", "-Xmx2G"})
@Warmup(iterations = 3, time = 2, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 3, timeUnit = TimeUnit.SECONDS)
@Threads(4) // Test with 4 concurrent threads
public class ConcurrentAuthenticationBenchmark {

    private JwtTokenService jwtTokenService;
    private RateLimitingService rateLimitingService;
    private BCryptPasswordEncoder passwordEncoder;
    
    // Test data arrays for concurrent access
    private String[] testPasswords;
    private String[] testPasswordHashes;
    private String[] testJwtTokens;
    private Long[] testUserIds;
    private String[] testEmails;

    @Setup(Level.Trial)
    public void setup() {
        // Initialize security properties
        SecurityProperties securityProperties = new SecurityProperties();
        SecurityProperties.Jwt jwtProperties = new SecurityProperties.Jwt();
        jwtProperties.setSecret("mySecretKeyForJWTTokenGenerationThatIsLongEnoughForHS512Algorithm");
        jwtProperties.setExpiration(3600000L); // 1 hour
        securityProperties.setJwt(jwtProperties);
        
        SecurityProperties.RateLimit rateLimitProperties = new SecurityProperties.RateLimit();
        rateLimitProperties.setMaxAttempts(100); // Higher limit for concurrent testing
        rateLimitProperties.setWindowMinutes(15);
        securityProperties.setRateLimit(rateLimitProperties);
        
        // Initialize services
        this.jwtTokenService = new JwtTokenService(securityProperties);
        
        CacheManager cacheManager = new ConcurrentMapCacheManager("rateLimitCache");
        this.rateLimitingService = new RateLimitingService(securityProperties, cacheManager);
        
        this.passwordEncoder = new BCryptPasswordEncoder(10); // Lower cost for benchmarking
        
        // Initialize test data arrays
        int dataSize = 1000;
        this.testPasswords = new String[dataSize];
        this.testPasswordHashes = new String[dataSize];
        this.testJwtTokens = new String[dataSize];
        this.testUserIds = new Long[dataSize];
        this.testEmails = new String[dataSize];
        
        for (int i = 0; i < dataSize; i++) {
            testPasswords[i] = "TestPassword" + i + "!";
            testPasswordHashes[i] = passwordEncoder.encode(testPasswords[i]);
            testUserIds[i] = (long) (i + 1);
            testEmails[i] = "user" + i + "@example.com";
            testJwtTokens[i] = jwtTokenService.generateToken(testUserIds[i], testEmails[i]);
        }
    }

    /**
     * Benchmark concurrent JWT token generation.
     * Simulates multiple users logging in simultaneously.
     */
    @Benchmark
    public String benchmarkConcurrentJwtTokenGeneration(Blackhole bh) {
        int index = ThreadLocalRandom.current().nextInt(testUserIds.length);
        String token = jwtTokenService.generateToken(testUserIds[index], testEmails[index]);
        bh.consume(token);
        return token;
    }

    /**
     * Benchmark concurrent JWT token validation.
     * Simulates multiple authenticated requests being processed simultaneously.
     */
    @Benchmark
    public JwtTokenService.JwtTokenInfo benchmarkConcurrentJwtTokenValidation(Blackhole bh) {
        int index = ThreadLocalRandom.current().nextInt(testJwtTokens.length);
        JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(testJwtTokens[index]);
        bh.consume(tokenInfo);
        return tokenInfo;
    }

    /**
     * Benchmark concurrent password verification.
     * Simulates multiple login attempts being processed simultaneously.
     */
    @Benchmark
    public boolean benchmarkConcurrentPasswordVerification(Blackhole bh) {
        int index = ThreadLocalRandom.current().nextInt(testPasswords.length);
        boolean matches = passwordEncoder.matches(testPasswords[index], testPasswordHashes[index]);
        bh.consume(matches);
        return matches;
    }

    /**
     * Benchmark concurrent rate limiting checks.
     * Simulates multiple users hitting rate limits simultaneously.
     */
    @Benchmark
    public boolean benchmarkConcurrentRateLimitingCheck(Blackhole bh) {
        // Use thread-specific keys to test concurrent access patterns
        long threadId = Thread.currentThread().getId();
        int randomSuffix = ThreadLocalRandom.current().nextInt(100);
        String key = "concurrent_user_" + threadId + "_" + randomSuffix;
        
        boolean allowed = rateLimitingService.isAllowed(key);
        bh.consume(allowed);
        return allowed;
    }

    /**
     * Benchmark concurrent token blacklisting.
     * Simulates multiple logout operations happening simultaneously.
     */
    @Benchmark
    public void benchmarkConcurrentTokenBlacklisting(Blackhole bh) {
        int index = ThreadLocalRandom.current().nextInt(testUserIds.length);
        // Generate a unique token for each operation to avoid conflicts
        String token = jwtTokenService.generateToken(
            testUserIds[index] + System.nanoTime(), 
            testEmails[index]
        );
        jwtTokenService.blacklistToken(token);
        bh.consume(token);
    }

    /**
     * Benchmark mixed authentication operations under load.
     * Simulates a realistic mix of authentication operations.
     */
    @Benchmark
    public void benchmarkMixedAuthenticationOperations(Blackhole bh) {
        int operation = ThreadLocalRandom.current().nextInt(4);
        int index = ThreadLocalRandom.current().nextInt(testUserIds.length);
        
        switch (operation) {
            case 0: // Token generation (login)
                String token = jwtTokenService.generateToken(testUserIds[index], testEmails[index]);
                bh.consume(token);
                break;
            case 1: // Token validation (authenticated request)
                JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(testJwtTokens[index]);
                bh.consume(tokenInfo);
                break;
            case 2: // Password verification (login)
                boolean matches = passwordEncoder.matches(testPasswords[index], testPasswordHashes[index]);
                bh.consume(matches);
                break;
            case 3: // Rate limiting check
                String key = "mixed_user_" + Thread.currentThread().getId() + "_" + index;
                boolean allowed = rateLimitingService.isAllowed(key);
                bh.consume(allowed);
                break;
        }
    }
}