package com.example.userauthentication.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation to mark methods that should be rate limited
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimited {
    
    /**
     * Maximum number of requests allowed within the time window
     */
    int maxAttempts() default 5;
    
    /**
     * Time window in minutes
     */
    int windowMinutes() default 15;
    
    /**
     * Key prefix for rate limiting (defaults to method name)
     */
    String keyPrefix() default "";
    
    /**
     * Whether to use IP address as part of the key
     */
    boolean useIpAddress() default true;
    
    /**
     * Whether to use user ID as part of the key (if authenticated)
     */
    boolean useUserId() default false;
}