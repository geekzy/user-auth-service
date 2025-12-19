package com.example.userauthentication.aspect;

import com.example.userauthentication.service.MetricsService;
import io.micrometer.core.instrument.Timer;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Aspect for monitoring performance of authentication operations.
 * Automatically tracks timing and success/failure rates for key operations.
 */
@Aspect
@Component
public class PerformanceMonitoringAspect {

    private static final Logger logger = LoggerFactory.getLogger(PerformanceMonitoringAspect.class);
    
    private final MetricsService metricsService;

    public PerformanceMonitoringAspect(MetricsService metricsService) {
        this.metricsService = metricsService;
    }

    /**
     * Monitor database operations in repository classes.
     */
    @Around("execution(* com.example.userauthentication.repository.*.*(..))")
    public Object monitorDatabaseOperations(ProceedingJoinPoint joinPoint) throws Throwable {
        Timer.Sample sample = Timer.start();
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        
        try {
            Object result = joinPoint.proceed();
            sample.stop(metricsService.getDatabaseOperationTimer());
            
            logger.debug("Database operation completed: {}.{} - Success", className, methodName);
            return result;
            
        } catch (Exception e) {
            sample.stop(metricsService.getDatabaseOperationTimer());
            logger.warn("Database operation failed: {}.{} - Error: {}", className, methodName, e.getMessage());
            throw e;
        }
    }

    /**
     * Monitor authentication operations and track success/failure rates.
     */
    @Around("execution(* com.example.userauthentication.security.CustomUserDetailsService.loadUserByUsername(..))")
    public Object monitorAuthentication(ProceedingJoinPoint joinPoint) throws Throwable {
        Timer.Sample sample = Timer.start();
        String email = (String) joinPoint.getArgs()[0];
        
        try {
            Object result = joinPoint.proceed();
            sample.stop(metricsService.getAuthenticationTimer());
            
            // Record successful authentication
            metricsService.recordAuthenticationSuccess();
            logger.debug("Authentication successful for user: {}", email);
            return result;
            
        } catch (Exception e) {
            sample.stop(metricsService.getAuthenticationTimer());
            
            // Record failed authentication
            metricsService.recordAuthenticationFailure();
            logger.warn("Authentication failed for user: {} - Error: {}", email, e.getMessage());
            throw e;
        }
    }

    /**
     * Monitor JWT token operations for performance tracking.
     */
    @Around("execution(* com.example.userauthentication.security.JwtTokenService.generateToken(..))")
    public Object monitorJwtTokenGeneration(ProceedingJoinPoint joinPoint) throws Throwable {
        Timer.Sample sample = Timer.start();
        
        try {
            Object result = joinPoint.proceed();
            sample.stop(metricsService.getAuthenticationTimer());
            
            metricsService.recordJwtTokenGeneration();
            logger.debug("JWT token generated successfully");
            return result;
            
        } catch (Exception e) {
            sample.stop(metricsService.getAuthenticationTimer());
            logger.error("JWT token generation failed: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Monitor JWT token validation operations.
     */
    @Around("execution(* com.example.userauthentication.security.JwtTokenService.validateToken(..))")
    public Object monitorJwtTokenValidation(ProceedingJoinPoint joinPoint) throws Throwable {
        Timer.Sample sample = Timer.start();
        
        try {
            Object result = joinPoint.proceed();
            sample.stop(metricsService.getAuthenticationTimer());
            
            metricsService.recordJwtTokenValidation();
            
            if (result != null) {
                logger.debug("JWT token validation successful");
            } else {
                logger.debug("JWT token validation failed - invalid token");
            }
            
            return result;
            
        } catch (Exception e) {
            sample.stop(metricsService.getAuthenticationTimer());
            logger.error("JWT token validation error: {}", e.getMessage());
            throw e;
        }
    }

    /**
     * Monitor rate limiting operations for performance.
     */
    @Around("execution(* com.example.userauthentication.security.RateLimitingService.isAllowed(..))")
    public Object monitorRateLimiting(ProceedingJoinPoint joinPoint) throws Throwable {
        Timer.Sample sample = Timer.start();
        String key = (String) joinPoint.getArgs()[0];
        
        try {
            Object result = joinPoint.proceed();
            sample.stop(metricsService.getAuthenticationTimer());
            
            Boolean allowed = (Boolean) result;
            if (!allowed) {
                metricsService.recordRateLimitViolation();
                logger.warn("Rate limit violation for key: {}", key);
            } else {
                logger.debug("Rate limit check passed for key: {}", key);
            }
            
            return result;
            
        } catch (Exception e) {
            sample.stop(metricsService.getAuthenticationTimer());
            logger.error("Rate limiting check error for key: {} - Error: {}", key, e.getMessage());
            throw e;
        }
    }
}