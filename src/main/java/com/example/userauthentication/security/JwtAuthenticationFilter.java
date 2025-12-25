package com.example.userauthentication.security;

import com.example.userauthentication.service.SessionService;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.LocalDateTime;

/**
 * JWT Authentication Filter that validates JWT tokens and manages session extension.
 * Implements OncePerRequestFilter for JWT validation with automatic session extension,
 * blacklist checking, and performance monitoring.
 * 
 * Requirements: 6.1, 6.2
 */
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final int SESSION_EXTENSION_THRESHOLD_MINUTES = 15; // Extend session if less than 15 minutes remaining

    private final JwtTokenService jwtTokenService;
    private final UserDetailsService userDetailsService;
    private final SessionService sessionService;
    
    // Performance monitoring metrics
    private final Counter jwtValidationAttempts;
    private final Counter jwtValidationSuccesses;
    private final Counter jwtValidationFailures;
    private final Counter sessionExtensions;
    private final Counter blacklistedTokenAttempts;
    private final Timer jwtProcessingTimer;

    public JwtAuthenticationFilter(JwtTokenService jwtTokenService, 
                                 UserDetailsService userDetailsService,
                                 SessionService sessionService,
                                 MeterRegistry meterRegistry) {
        this.jwtTokenService = jwtTokenService;
        this.userDetailsService = userDetailsService;
        this.sessionService = sessionService;
        
        // Initialize performance metrics
        this.jwtValidationAttempts = Counter.builder("auth.jwt.validation.attempts")
                .description("Total number of JWT validation attempts")
                .register(meterRegistry);
        this.jwtValidationSuccesses = Counter.builder("auth.jwt.validation.successes")
                .description("Total number of successful JWT validations")
                .register(meterRegistry);
        this.jwtValidationFailures = Counter.builder("auth.jwt.validation.failures")
                .description("Total number of failed JWT validations")
                .register(meterRegistry);
        this.sessionExtensions = Counter.builder("auth.jwt.session.extensions")
                .description("Total number of automatic session extensions")
                .register(meterRegistry);
        this.blacklistedTokenAttempts = Counter.builder("auth.jwt.blacklisted.attempts")
                .description("Total number of blacklisted token access attempts")
                .register(meterRegistry);
        this.jwtProcessingTimer = Timer.builder("auth.jwt.processing.duration")
                .description("Time taken to process JWT authentication")
                .register(meterRegistry);
    }





    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        Timer.Sample sample = Timer.start();
        String clientIp = getClientIpAddress(request);
        
        try {
            String jwt = extractJwtFromRequest(request);

            if (jwt != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                jwtValidationAttempts.increment();
                
                // Check if token is blacklisted first (performance optimization)
                if (jwtTokenService.isTokenBlacklisted(jwt)) {
                    blacklistedTokenAttempts.increment();
                    logger.debug("Blacklisted token access attempt from IP: {}", clientIp);
                    jwtValidationFailures.increment();
                } else {
                    // Validate JWT token
                    JwtTokenService.JwtTokenInfo tokenInfo = jwtTokenService.validateToken(jwt);

                    if (tokenInfo != null && !tokenInfo.isExpired()) {
                        try {
                            // Load user details
                            UserDetails userDetails = userDetailsService.loadUserByUsername(tokenInfo.getEmail());

                            // Create authentication token
                            UsernamePasswordAuthenticationToken authentication = 
                                new UsernamePasswordAuthenticationToken(
                                    userDetails, 
                                    null, 
                                    userDetails.getAuthorities()
                                );
                            
                            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                            // Set authentication in security context
                            SecurityContextHolder.getContext().setAuthentication(authentication);
                            
                            // Automatic session extension if token is near expiry
                            handleAutomaticSessionExtension(tokenInfo, jwt, clientIp);
                            
                            jwtValidationSuccesses.increment();
                            logger.debug("JWT authentication successful for user: {} from IP: {}", 
                                       tokenInfo.getEmail(), clientIp);
                            
                        } catch (Exception e) {
                            logger.warn("Failed to load user details for email: {} - {}", 
                                      tokenInfo.getEmail(), e.getMessage());
                            jwtValidationFailures.increment();
                        }
                    } else {
                        jwtValidationFailures.increment();
                        if (tokenInfo == null) {
                            logger.debug("JWT token validation failed from IP: {}", clientIp);
                        } else {
                            logger.debug("JWT token expired for user: {} from IP: {}", 
                                       tokenInfo.getEmail(), clientIp);
                        }
                    }
                }
            }
        } catch (Exception e) {
            jwtValidationFailures.increment();
            logger.error("Cannot set user authentication from IP: {} - {}", clientIp, e.getMessage());
        } finally {
            sample.stop(jwtProcessingTimer);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Handles automatic session extension for tokens that are near expiry.
     * Extends session if the token will expire within the threshold time.
     * 
     * @param tokenInfo the validated JWT token information
     * @param jwt the raw JWT token string
     * @param clientIp the client's IP address for logging
     */
    private void handleAutomaticSessionExtension(JwtTokenService.JwtTokenInfo tokenInfo, String jwt, String clientIp) {
        try {
            // Check if token is near expiry (within threshold minutes)
            LocalDateTime now = LocalDateTime.now();
            LocalDateTime expiryThreshold = now.plusMinutes(SESSION_EXTENSION_THRESHOLD_MINUTES);
            
            if (tokenInfo.getExpiresAt().isBefore(expiryThreshold)) {
                // Token is near expiry, attempt to extend session
                logger.debug("Token near expiry for user: {}, attempting session extension", tokenInfo.getEmail());
                
                // Note: In a full implementation, you might want to:
                // 1. Find the associated session ID from the database
                // 2. Extend the session in the database
                // 3. Optionally issue a new JWT token with extended expiry
                
                // For now, we'll use a simplified approach by extending any active sessions for this user
                boolean hasActiveSessions = sessionService.hasActiveSession(tokenInfo.getUserId());
                if (hasActiveSessions) {
                    // Extend all active sessions for this user by 30 minutes
                    int extendedSessions = extendUserSessions(tokenInfo.getUserId(), 30);
                    if (extendedSessions > 0) {
                        sessionExtensions.increment();
                        logger.debug("Extended {} sessions for user: {} from IP: {}", 
                                   extendedSessions, tokenInfo.getEmail(), clientIp);
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to extend session for user: {} - {}", tokenInfo.getEmail(), e.getMessage());
        }
    }

    /**
     * Extends all active sessions for a user.
     * 
     * @param userId the user ID whose sessions should be extended
     * @param extensionMinutes number of minutes to extend sessions
     * @return number of sessions that were extended
     */
    private int extendUserSessions(Long userId, int extensionMinutes) {
        try {
            var activeSessions = sessionService.getActiveUserSessions(userId);
            int extendedCount = 0;
            
            for (var session : activeSessions) {
                if (sessionService.extendSessionExpiration(session.getId(), extensionMinutes)) {
                    extendedCount++;
                }
            }
            
            return extendedCount;
        } catch (Exception e) {
            logger.error("Error extending sessions for user ID: {} - {}", userId, e.getMessage());
            return 0;
        }
    }

    /**
     * Extracts the client's real IP address, considering proxy headers.
     * 
     * @param request the HTTP request
     * @return the client's IP address
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(xRealIp)) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Extract JWT token from Authorization header
     */
    private String extractJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        
        return null;
    }
}