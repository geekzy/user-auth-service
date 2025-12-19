package com.example.userauthentication.benchmark;

import com.example.userauthentication.config.SecurityProperties;
import com.example.userauthentication.security.JwtTokenService;
import com.example.userauthentication.security.RateLimitingService;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.springframework.cache.CacheManager;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.concurrent.TimeUnit;

/**
 * JMH benchmarks for critical authentication paths.
 * 
 * **Feature: user-authentication, Performance benchmarks for authentication operations**
 * 
 * Requirements: 2.1 (login performance), 2.5 (account locking performance), 5.4 (rate limiting performance)
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Benchmark)
@Fork(value = 1, jvmArgs = {"-Xms2G", "-Xmx2G"})
@Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
public class AuthenticationBenchmark {

    private JwtTokenService jwtTokenService;
    private RateLimitingService rateLimitingService;
    private BCryptPasswordEncoder passwordEncoder;
    
    // Test data
    private String testPassword;
    private String testPasswordHash;
    private String testJwtToken;
    private Long testUserId;
    private String testEmail;

    @Setup(Level.Trial)
    public void setup() {
        // Initialize security properties
        SecurityProperties securityProperties = new SecurityProperties();
        SecurityProperties.Jwt jwtProperties = new SecurityProperties.Jwt();
        jwtProperties.setSecret("mySecretKeyForJWTTokenGenerationThatIsLongEnoughForHS512Algorithm");
        jwtProperties.setExpiration(3600000L); // 1 hour
        securityProperties.setJwt(jwtProperties);
        
        SecurityProperties.RateLimit rateLimitProperties = new SecurityProperties.RateLimit();
        rateLimitProperties.setMaxAttempts(5);
        rateLimitProperties.setWindowMinutes(15);
        securityProperties.setRateLimit(rateLimitProperties);
        
        // Initialize services
        this.jwtTokenService = new JwtTokenService(securityProperties);
        
        CacheManager cacheManager = new ConcurrentMapCacheManager("rateLimitCache");
        this.rateLimitingService = new RateLimitingService(securityProperties, cacheManager);
        
        this.passwordEncoder = new BCryptPasswordEncoder(12);
        
        // Initialize test data
        this.testPassword = "TestPassword123!";
        this.testPasswordHash = passwordEncoder.encode(testPassword);
        this.testUserId = 12345L;
        this.testEmail = "test@example.com";
        this.testJwtToken = jwtTokenService.generateToken(testUserId, testEmail);
    }

    /**
     * Benchmark JWT token generation performance.
     * Critical for login operations (Requirement 2.1).
     */
    @Benchmark
    public String benchmarkJwtTokenGeneration(Blackhole bh) {
        String token = jwtTokenService.generateToken(testUserId, testEmail);
        bh.consume(token);
        return token;
    }

    /**
     * Benchmark JWT token validation performance.
     * Critical for every authenticated request (Requirement 2.1).
     */
    @Benchmark
    public JwtTokenService.JwtTokenInfo benchmarkJwtTokenValidation(Blackhole bh) {
        JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(testJwtToken);
        bh.consume(tokenInfo);
        return tokenInfo;
    }

    /**
     * Benchmark password hashing performance.
     * Critical for user registration and password changes (Requirement 2.1).
     */
    @Benchmark
    public String benchmarkPasswordHashing(Blackhole bh) {
        String hash = passwordEncoder.encode(testPassword);
        bh.consume(hash);
        return hash;
    }

    /**
     * Benchmark password verification performance.
     * Critical for login operations (Requirement 2.1).
     */
    @Benchmark
    public boolean benchmarkPasswordVerification(Blackhole bh) {
        boolean matches = passwordEncoder.matches(testPassword, testPasswordHash);
        bh.consume(matches);
        return matches;
    }

    /**
     * Benchmark rate limiting check performance.
     * Critical for preventing brute force attacks (Requirement 5.4).
     */
    @Benchmark
    public boolean benchmarkRateLimitingCheck(Blackhole bh) {
        // Use different keys to avoid hitting rate limits during benchmark
        String key = "benchmark_user_" + System.nanoTime();
        boolean allowed = rateLimitingService.isAllowed(key);
        bh.consume(allowed);
        return allowed;
    }

    /**
     * Benchmark JWT refresh token generation performance.
     * Important for session management (Requirement 2.1).
     */
    @Benchmark
    public String benchmarkRefreshTokenGeneration(Blackhole bh) {
        String refreshToken = jwtTokenService.generateRefreshToken(testUserId, testEmail);
        bh.consume(refreshToken);
        return refreshToken;
    }

    /**
     * Benchmark token blacklisting performance.
     * Critical for logout operations (Requirement 2.1).
     */
    @Benchmark
    public void benchmarkTokenBlacklisting(Blackhole bh) {
        // Generate a unique token for each benchmark iteration
        String token = jwtTokenService.generateToken(testUserId + System.nanoTime(), testEmail);
        jwtTokenService.blacklistToken(token);
        bh.consume(token);
    }

    /**
     * Benchmark blacklist checking performance.
     * Critical for every authenticated request (Requirement 2.1).
     */
    @Benchmark
    public boolean benchmarkBlacklistCheck(Blackhole bh) {
        boolean isBlacklisted = jwtTokenService.isTokenBlacklisted(testJwtToken);
        bh.consume(isBlacklisted);
        return isBlacklisted;
    }
}