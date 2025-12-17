package com.example.userauthentication.security;

import com.example.userauthentication.security.CustomUserDetailsService.CustomUserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.HashMap;
import java.util.Map;

@Aspect
@Component
public class RateLimitingAspect {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitingAspect.class);

    private final RateLimitingService rateLimitingService;

    public RateLimitingAspect(RateLimitingService rateLimitingService) {
        this.rateLimitingService = rateLimitingService;
    }

    @Around("@annotation(rateLimited)")
    public Object enforceRateLimit(ProceedingJoinPoint joinPoint, RateLimited rateLimited) throws Throwable {
        
        String rateLimitKey = buildRateLimitKey(joinPoint, rateLimited);
        
        boolean isAllowed = rateLimitingService.isAllowed(
            rateLimitKey, 
            rateLimited.maxAttempts(), 
            rateLimited.windowMinutes()
        );

        if (!isAllowed) {
            logger.warn("Rate limit exceeded for key: {}", rateLimitKey);
            
            // Get remaining time until reset
            long timeUntilReset = rateLimitingService.getTimeUntilReset(rateLimitKey);
            
            // Create rate limit exceeded response
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Rate limit exceeded");
            errorResponse.put("message", "Too many requests. Please try again later.");
            errorResponse.put("retryAfterSeconds", timeUntilReset);
            errorResponse.put("maxAttempts", rateLimited.maxAttempts());
            errorResponse.put("windowMinutes", rateLimited.windowMinutes());
            
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header("Retry-After", String.valueOf(timeUntilReset))
                    .body(errorResponse);
        }

        // Proceed with the original method
        return joinPoint.proceed();
    }

    private String buildRateLimitKey(ProceedingJoinPoint joinPoint, RateLimited rateLimited) {
        StringBuilder keyBuilder = new StringBuilder();
        
        // Add key prefix (method name if not specified)
        String keyPrefix = rateLimited.keyPrefix();
        if (keyPrefix.isEmpty()) {
            keyPrefix = joinPoint.getSignature().getName();
        }
        keyBuilder.append(keyPrefix);

        // Add IP address if requested
        if (rateLimited.useIpAddress()) {
            String ipAddress = getClientIpAddress();
            if (ipAddress != null) {
                keyBuilder.append(":ip:").append(ipAddress);
            }
        }

        // Add user ID if requested and user is authenticated
        if (rateLimited.useUserId()) {
            Long userId = getCurrentUserId();
            if (userId != null) {
                keyBuilder.append(":user:").append(userId);
            }
        }

        return keyBuilder.toString();
    }

    private String getClientIpAddress() {
        ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        if (attributes == null) {
            return null;
        }

        HttpServletRequest request = attributes.getRequest();
        
        // Check for IP address in various headers (for proxy/load balancer scenarios)
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("X-Real-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }

        // Handle multiple IPs in X-Forwarded-For header
        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }

        return ipAddress;
    }

    private Long getCurrentUserId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.isAuthenticated() && 
            authentication.getPrincipal() instanceof CustomUserPrincipal) {
            
            CustomUserPrincipal userPrincipal = (CustomUserPrincipal) authentication.getPrincipal();
            return userPrincipal.getUserId();
        }
        
        return null;
    }
}