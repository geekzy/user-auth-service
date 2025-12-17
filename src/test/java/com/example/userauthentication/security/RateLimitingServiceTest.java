package com.example.userauthentication.security;

import com.example.userauthentication.config.SecurityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Nested;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for rate limiting functionality.
 * Tests rate limiting enforcement, threshold behavior, and sliding window functionality.
 * 
 * Requirements: 5.4 - Rate limiting enforcement
 */
class RateLimitingServiceTest {

    private RateLimitingService rateLimitingService;
    private SecurityProperties securityProperties;
    
    @Mock
    private CacheManager cacheManager;
    
    @Mock
    private Cache cache;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        
        // Set up security properties
        securityProperties = new SecurityProperties();
        SecurityProperties.RateLimit rateLimit = new SecurityProperties.RateLimit();
        rateLimit.setMaxAttempts(5);
        rateLimit.setWindowMinutes(15);
        securityProperties.setRateLimit(rateLimit);
        
        // Mock cache manager to return null (use fallback storage)
        when(cacheManager.getCache(anyString())).thenReturn(null);
        
        rateLimitingService = new RateLimitingService(securityProperties, cacheManager);
    }

    @Nested
    class RateLimitEnforcementTests {

        @Test
        void testFirstRequestIsAllowed() {
            // Test that first request is always allowed
            String key = "test-key-1";
            
            boolean isAllowed = rateLimitingService.isAllowed(key, 5, 15);
            
            assertTrue(isAllowed, "First request should be allowed");
        }

        @Test
        void testRequestsWithinLimitAreAllowed() {
            // Test that requests within limit are allowed
            String key = "test-key-2";
            int maxAttempts = 3;
            
            // Make requests within limit
            for (int i = 0; i < maxAttempts; i++) {
                boolean isAllowed = rateLimitingService.isAllowed(key, maxAttempts, 15);
                assertTrue(isAllowed, "Request " + (i + 1) + " should be allowed");
            }
        }

        @Test
        void testRequestsExceedingLimitAreBlocked() {
            // Test that requests exceeding limit are blocked
            String key = "test-key-3";
            int maxAttempts = 3;
            
            // Make requests up to limit
            for (int i = 0; i < maxAttempts; i++) {
                rateLimitingService.isAllowed(key, maxAttempts, 15);
            }
            
            // Next request should be blocked
            boolean isAllowed = rateLimitingService.isAllowed(key, maxAttempts, 15);
            assertFalse(isAllowed, "Request exceeding limit should be blocked");
        }

        @Test
        void testMultipleKeysAreIndependent() {
            // Test that different keys have independent rate limits
            String key1 = "test-key-4a";
            String key2 = "test-key-4b";
            int maxAttempts = 2;
            
            // Exhaust limit for key1
            rateLimitingService.isAllowed(key1, maxAttempts, 15);
            rateLimitingService.isAllowed(key1, maxAttempts, 15);
            boolean key1Blocked = rateLimitingService.isAllowed(key1, maxAttempts, 15);
            
            // key2 should still be allowed
            boolean key2Allowed = rateLimitingService.isAllowed(key2, maxAttempts, 15);
            
            assertFalse(key1Blocked, "Key1 should be blocked after exceeding limit");
            assertTrue(key2Allowed, "Key2 should be allowed (independent limit)");
        }

        @Test
        void testDefaultConfigurationIsUsed() {
            // Test that default configuration from properties is used
            String key = "test-key-5";
            
            // Use default configuration (5 attempts, 15 minutes)
            boolean isAllowed = rateLimitingService.isAllowed(key);
            assertTrue(isAllowed, "Request with default config should be allowed");
        }
    }

    @Nested
    class SlidingWindowTests {

        @Test
        void testWindowResetAfterExpiration() throws InterruptedException {
            // Test that rate limit resets after window expiration
            String key = "test-key-6";
            int maxAttempts = 1;
            int windowMinutes = 0; // Use 0 minutes for immediate expiration in test
            
            // First request creates entry with 1 attempt
            boolean firstAllowed = rateLimitingService.isAllowed(key, maxAttempts, windowMinutes);
            assertTrue(firstAllowed, "First request should be allowed");
            
            // With 0 minutes window, every subsequent request should reset the window
            // So all requests should be allowed since window expires immediately
            boolean secondAllowed = rateLimitingService.isAllowed(key, maxAttempts, windowMinutes);
            assertTrue(secondAllowed, "Second request should be allowed due to immediate window expiration");
            
            boolean thirdAllowed = rateLimitingService.isAllowed(key, maxAttempts, windowMinutes);
            assertTrue(thirdAllowed, "Third request should be allowed due to immediate window expiration");
        }

        @Test
        void testRemainingAttemptsCalculation() {
            // Test calculation of remaining attempts
            String key = "test-key-7";
            int maxAttempts = 5;
            
            // Initially should have all attempts remaining
            int remaining = rateLimitingService.getRemainingAttempts(key, maxAttempts);
            assertEquals(maxAttempts, remaining, "Should have all attempts remaining initially");
            
            // Make some requests
            rateLimitingService.isAllowed(key, maxAttempts, 15);
            rateLimitingService.isAllowed(key, maxAttempts, 15);
            
            // Should have fewer attempts remaining
            remaining = rateLimitingService.getRemainingAttempts(key, maxAttempts);
            assertEquals(3, remaining, "Should have 3 attempts remaining after 2 requests");
        }

        @Test
        void testTimeUntilResetCalculation() {
            // Test calculation of time until reset
            String key = "test-key-8";
            int windowMinutes = 10;
            
            // Make a request to start the window
            rateLimitingService.isAllowed(key, 5, windowMinutes);
            
            // Should have time remaining (approximately 10 minutes = 600 seconds)
            long timeUntilReset = rateLimitingService.getTimeUntilReset(key);
            assertTrue(timeUntilReset > 0, "Should have time remaining until reset");
            assertTrue(timeUntilReset <= 600, "Time until reset should be <= 600 seconds");
        }

        @Test
        void testTimeUntilResetForNonExistentKey() {
            // Test time until reset for non-existent key
            String key = "non-existent-key";
            
            long timeUntilReset = rateLimitingService.getTimeUntilReset(key);
            assertEquals(0, timeUntilReset, "Non-existent key should have 0 time until reset");
        }
    }

    @Nested
    class RateLimitManagementTests {

        @Test
        void testClearRateLimit() {
            // Test clearing rate limit for a key
            String key = "test-key-9";
            int maxAttempts = 2;
            
            // Exhaust the limit
            rateLimitingService.isAllowed(key, maxAttempts, 15);
            rateLimitingService.isAllowed(key, maxAttempts, 15);
            
            // Should be blocked
            boolean blockedBefore = rateLimitingService.isAllowed(key, maxAttempts, 15);
            assertFalse(blockedBefore, "Should be blocked before clearing");
            
            // Clear the rate limit
            rateLimitingService.clearRateLimit(key);
            
            // Should be allowed again
            boolean allowedAfter = rateLimitingService.isAllowed(key, maxAttempts, 15);
            assertTrue(allowedAfter, "Should be allowed after clearing rate limit");
        }

        @Test
        void testCleanupExpiredEntries() {
            // Test cleanup of expired entries
            String key1 = "test-key-10a";
            String key2 = "test-key-10b";
            
            // Create entries with different expiration times
            rateLimitingService.isAllowed(key1, 5, 0); // Expires immediately
            rateLimitingService.isAllowed(key2, 5, 60); // Expires in 1 hour
            
            // Wait for first entry to expire
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            // Cleanup expired entries
            rateLimitingService.cleanupExpiredEntries();
            
            // First key should be reset (expired), second should still be tracked
            int remaining1 = rateLimitingService.getRemainingAttempts(key1, 5);
            int remaining2 = rateLimitingService.getRemainingAttempts(key2, 5);
            
            assertEquals(5, remaining1, "Expired key should be reset");
            assertEquals(4, remaining2, "Non-expired key should still be tracked");
        }
    }

    @Nested
    class CacheIntegrationTests {

        @Test
        void testCacheIntegration() {
            // Test integration with cache manager
            when(cacheManager.getCache("rateLimitCache")).thenReturn(cache);
            when(cache.get(anyString())).thenReturn(null);
            
            RateLimitingService serviceWithCache = new RateLimitingService(securityProperties, cacheManager);
            
            String key = "test-key-11";
            boolean isAllowed = serviceWithCache.isAllowed(key, 5, 15);
            
            assertTrue(isAllowed, "Request should be allowed with cache integration");
            verify(cache, atLeastOnce()).put(anyString(), any());
        }

        @Test
        void testFallbackStorageWhenCacheUnavailable() {
            // Test fallback to in-memory storage when cache is unavailable
            when(cacheManager.getCache(anyString())).thenReturn(null);
            
            String key = "test-key-12";
            boolean isAllowed = rateLimitingService.isAllowed(key, 5, 15);
            
            assertTrue(isAllowed, "Should work with fallback storage when cache unavailable");
        }

        @Test
        void testCacheRetrievalAndStorage() {
            // Test cache retrieval and storage
            when(cacheManager.getCache("rateLimitCache")).thenReturn(cache);
            
            RateLimitingService.RateLimitEntry entry = new RateLimitingService.RateLimitEntry(
                2, LocalDateTime.now(), LocalDateTime.now().plusMinutes(15));
            Cache.ValueWrapper wrapper = mock(Cache.ValueWrapper.class);
            when(wrapper.get()).thenReturn(entry);
            when(cache.get(anyString())).thenReturn(wrapper);
            
            RateLimitingService serviceWithCache = new RateLimitingService(securityProperties, cacheManager);
            
            String key = "test-key-13";
            int remaining = serviceWithCache.getRemainingAttempts(key, 5);
            
            assertEquals(3, remaining, "Should retrieve entry from cache correctly");
        }
    }

    @Nested
    class RateLimitEntryTests {

        @Test
        void testRateLimitEntryCreation() {
            // Test RateLimitEntry creation and getters
            LocalDateTime start = LocalDateTime.now();
            LocalDateTime end = start.plusMinutes(15);
            
            RateLimitingService.RateLimitEntry entry = 
                new RateLimitingService.RateLimitEntry(3, start, end);
            
            assertEquals(3, entry.getAttempts(), "Attempts should match constructor value");
            assertEquals(start, entry.getWindowStart(), "Window start should match constructor value");
            assertEquals(end, entry.getWindowEnd(), "Window end should match constructor value");
        }

        @Test
        void testRateLimitEntryIncrement() {
            // Test incrementing attempts in RateLimitEntry
            LocalDateTime start = LocalDateTime.now();
            LocalDateTime end = start.plusMinutes(15);
            
            RateLimitingService.RateLimitEntry entry = 
                new RateLimitingService.RateLimitEntry(1, start, end);
            
            assertEquals(1, entry.getAttempts(), "Initial attempts should be 1");
            
            entry.incrementAttempts();
            assertEquals(2, entry.getAttempts(), "Attempts should be incremented to 2");
            
            entry.incrementAttempts();
            assertEquals(3, entry.getAttempts(), "Attempts should be incremented to 3");
        }
    }

    @Nested
    class EdgeCaseTests {

        @Test
        void testZeroMaxAttempts() {
            // Test behavior with zero max attempts
            String key = "test-key-14";
            
            // First request is always allowed (creates entry with 1 attempt)
            boolean firstAllowed = rateLimitingService.isAllowed(key, 0, 15);
            assertTrue(firstAllowed, "First request should be allowed even with zero max attempts");
            
            // Second request should be blocked (1 >= 0)
            boolean secondAllowed = rateLimitingService.isAllowed(key, 0, 15);
            assertFalse(secondAllowed, "Second request should be blocked with zero max attempts");
        }

        @Test
        void testNegativeMaxAttempts() {
            // Test behavior with negative max attempts
            String key = "test-key-15";
            
            // First request is always allowed (creates entry with 1 attempt)
            boolean firstAllowed = rateLimitingService.isAllowed(key, -1, 15);
            assertTrue(firstAllowed, "First request should be allowed even with negative max attempts");
            
            // Second request should be blocked (1 >= -1)
            boolean secondAllowed = rateLimitingService.isAllowed(key, -1, 15);
            assertFalse(secondAllowed, "Second request should be blocked with negative max attempts");
        }

        @Test
        void testZeroWindowMinutes() {
            // Test behavior with zero window minutes (immediate expiration)
            String key = "test-key-16";
            
            // First request should be allowed
            boolean first = rateLimitingService.isAllowed(key, 1, 0);
            assertTrue(first, "First request should be allowed even with zero window");
            
            // Second request should also be allowed due to immediate expiration
            boolean second = rateLimitingService.isAllowed(key, 1, 0);
            assertTrue(second, "Second request should be allowed due to immediate window expiration");
        }

        @Test
        void testEmptyKey() {
            // Test behavior with empty key
            String key = "";
            
            boolean isAllowed = rateLimitingService.isAllowed(key, 5, 15);
            assertTrue(isAllowed, "Empty key should be handled gracefully");
        }

        @Test
        void testNullKey() {
            // Test behavior with null key
            String key = null;
            
            // This should not throw an exception
            assertDoesNotThrow(() -> {
                rateLimitingService.isAllowed(key, 5, 15);
            }, "Null key should be handled gracefully");
        }

        @Test
        void testVeryLargeMaxAttempts() {
            // Test behavior with very large max attempts
            String key = "test-key-17";
            int largeMaxAttempts = Integer.MAX_VALUE;
            
            boolean isAllowed = rateLimitingService.isAllowed(key, largeMaxAttempts, 15);
            assertTrue(isAllowed, "Should handle very large max attempts");
            
            int remaining = rateLimitingService.getRemainingAttempts(key, largeMaxAttempts);
            assertEquals(largeMaxAttempts - 1, remaining, "Should calculate remaining attempts correctly");
        }

        @Test
        void testConcurrentAccess() throws InterruptedException {
            // Test concurrent access to rate limiting service
            String key = "test-key-18";
            int maxAttempts = 10;
            int threadCount = 5;
            
            Thread[] threads = new Thread[threadCount];
            boolean[] results = new boolean[threadCount];
            
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    results[index] = rateLimitingService.isAllowed(key, maxAttempts, 15);
                });
            }
            
            // Start all threads
            for (Thread thread : threads) {
                thread.start();
            }
            
            // Wait for all threads to complete
            for (Thread thread : threads) {
                thread.join();
            }
            
            // All requests should be allowed since we're within the limit
            for (int i = 0; i < threadCount; i++) {
                assertTrue(results[i], "Concurrent request " + i + " should be allowed");
            }
        }
    }
}