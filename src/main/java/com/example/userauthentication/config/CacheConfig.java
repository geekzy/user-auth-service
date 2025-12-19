package com.example.userauthentication.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;

@Configuration
@EnableCaching
@EnableScheduling
public class CacheConfig {

    /**
     * Configure cache manager for rate limiting and other caching needs
     * In production, this could be replaced with Redis or other distributed cache
     */
    @Bean
    public CacheManager cacheManager() {
        ConcurrentMapCacheManager cacheManager = new ConcurrentMapCacheManager();
        
        // Pre-create caches
        cacheManager.setCacheNames(java.util.Arrays.asList(
            "rateLimitCache",
            "sessionCache",
            "userCache",
            "users",           // For user entity caching
            "userExists"       // For user existence checks
        ));
        
        // Allow dynamic cache creation
        cacheManager.setAllowNullValues(false);
        
        return cacheManager;
    }

    /**
     * Scheduled task to clean up expired cache entries
     * Runs every 5 minutes
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
    public void cleanupExpiredCacheEntries() {
        // This would be handled automatically by Redis TTL in production
        // For in-memory cache, we rely on the services to clean up their own entries
    }
}