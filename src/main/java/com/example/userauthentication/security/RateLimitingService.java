package com.example.userauthentication.security;

import com.example.userauthentication.config.SecurityProperties;
import io.micrometer.core.annotation.Timed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Service
public class RateLimitingService {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingService.class);
    private static final String RATE_LIMIT_CACHE = "rateLimitCache";

    private final SecurityProperties securityProperties;
    private final CacheManager cacheManager;
    
    // Fallback in-memory storage if cache is not available
    private final ConcurrentMap<String, RateLimitEntry> fallbackStorage = new ConcurrentHashMap<>();

    public RateLimitingService(SecurityProperties securityProperties, CacheManager cacheManager) {
        this.securityProperties = securityProperties;
        this.cacheManager = cacheManager;
    }

    /**
     * Check if the request is allowed based on rate limiting rules
     */
    @Timed(value = "auth.rate.limit.check.time", description = "Time taken to check rate limiting rules")
    public boolean isAllowed(String key, int maxAttempts, int windowMinutes) {
        String rateLimitKey = "rate_limit:" + key;
        
        RateLimitEntry entry = getRateLimitEntry(rateLimitKey);
        LocalDateTime now = LocalDateTime.now();
        
        if (entry == null) {
            // First request - create new entry
            entry = new RateLimitEntry(1, now, now.plusMinutes(windowMinutes));
            storeRateLimitEntry(rateLimitKey, entry);
            logger.debug("First request for key: {}", key);
            return true;
        }
        
        // Check if window has expired
        if (now.isAfter(entry.getWindowEnd())) {
            // Window expired - reset counter
            entry = new RateLimitEntry(1, now, now.plusMinutes(windowMinutes));
            storeRateLimitEntry(rateLimitKey, entry);
            logger.debug("Rate limit window expired for key: {}, resetting counter", key);
            return true;
        }
        
        // Check if limit exceeded
        if (entry.getAttempts() >= maxAttempts) {
            logger.warn("Rate limit exceeded for key: {}. Attempts: {}, Max: {}", 
                       key, entry.getAttempts(), maxAttempts);
            return false;
        }
        
        // Increment counter
        entry.incrementAttempts();
        storeRateLimitEntry(rateLimitKey, entry);
        
        logger.debug("Rate limit check passed for key: {}. Attempts: {}/{}", 
                    key, entry.getAttempts(), maxAttempts);
        return true;
    }

    /**
     * Check if request is allowed using default configuration
     */
    public boolean isAllowed(String key) {
        return isAllowed(key, 
                        securityProperties.getRateLimit().getMaxAttempts(),
                        securityProperties.getRateLimit().getWindowMinutes());
    }

    /**
     * Get remaining attempts for a key
     */
    public int getRemainingAttempts(String key, int maxAttempts) {
        String rateLimitKey = "rate_limit:" + key;
        RateLimitEntry entry = getRateLimitEntry(rateLimitKey);
        
        if (entry == null || LocalDateTime.now().isAfter(entry.getWindowEnd())) {
            return maxAttempts;
        }
        
        return Math.max(0, maxAttempts - entry.getAttempts());
    }

    /**
     * Get time until rate limit window resets
     */
    public long getTimeUntilReset(String key) {
        String rateLimitKey = "rate_limit:" + key;
        RateLimitEntry entry = getRateLimitEntry(rateLimitKey);
        
        if (entry == null) {
            return 0;
        }
        
        LocalDateTime now = LocalDateTime.now();
        if (now.isAfter(entry.getWindowEnd())) {
            return 0;
        }
        
        return ChronoUnit.SECONDS.between(now, entry.getWindowEnd());
    }

    /**
     * Clear rate limit for a specific key (for testing or admin purposes)
     */
    public void clearRateLimit(String key) {
        String rateLimitKey = "rate_limit:" + key;
        
        Cache cache = cacheManager.getCache(RATE_LIMIT_CACHE);
        if (cache != null) {
            cache.evict(rateLimitKey);
        }
        
        fallbackStorage.remove(rateLimitKey);
        logger.debug("Cleared rate limit for key: {}", key);
    }

    /**
     * Clean up expired entries (should be called periodically)
     */
    public void cleanupExpiredEntries() {
        LocalDateTime now = LocalDateTime.now();
        
        // Clean up fallback storage
        fallbackStorage.entrySet().removeIf(entry -> 
            now.isAfter(entry.getValue().getWindowEnd()));
        
        logger.debug("Cleaned up expired rate limit entries. Remaining entries: {}", 
                    fallbackStorage.size());
    }

    private RateLimitEntry getRateLimitEntry(String key) {
        // Try cache first
        Cache cache = cacheManager.getCache(RATE_LIMIT_CACHE);
        if (cache != null) {
            Cache.ValueWrapper wrapper = cache.get(key);
            if (wrapper != null) {
                return (RateLimitEntry) wrapper.get();
            }
        }
        
        // Fallback to in-memory storage
        return fallbackStorage.get(key);
    }

    private void storeRateLimitEntry(String key, RateLimitEntry entry) {
        // Store in cache if available
        Cache cache = cacheManager.getCache(RATE_LIMIT_CACHE);
        if (cache != null) {
            cache.put(key, entry);
        }
        
        // Also store in fallback storage
        fallbackStorage.put(key, entry);
    }

    /**
     * Rate limit entry to track attempts and window
     */
    public static class RateLimitEntry {
        private int attempts;
        private final LocalDateTime windowStart;
        private final LocalDateTime windowEnd;

        public RateLimitEntry(int attempts, LocalDateTime windowStart, LocalDateTime windowEnd) {
            this.attempts = attempts;
            this.windowStart = windowStart;
            this.windowEnd = windowEnd;
        }

        public int getAttempts() { return attempts; }
        public LocalDateTime getWindowStart() { return windowStart; }
        public LocalDateTime getWindowEnd() { return windowEnd; }

        public void incrementAttempts() {
            this.attempts++;
        }
    }
}