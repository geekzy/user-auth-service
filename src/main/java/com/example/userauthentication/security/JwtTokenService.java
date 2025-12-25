package com.example.userauthentication.security;

import com.example.userauthentication.config.SecurityProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.micrometer.core.annotation.Timed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class JwtTokenService {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenService.class);
    
    private final SecurityProperties securityProperties;
    private final SecretKey secretKey;
    
    // In-memory blacklist for revoked tokens (in production, use Redis or database)
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    public JwtTokenService(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
        this.secretKey = Keys.hmacShaKeyFor(securityProperties.getJwt().getSecret().getBytes());
    }

    /**
     * Generate JWT token for authenticated user
     */
    @Timed(value = "auth.jwt.token.generation.time", description = "Time taken to generate JWT token")
    public String generateToken(Long userId, String email) {
        Instant now = Instant.now();
        Instant expiration = now.plusMillis(securityProperties.getJwt().getExpiration());

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("type", "access")
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Generate refresh token with longer expiration
     */
    @Timed(value = "auth.jwt.refresh.token.generation.time", description = "Time taken to generate JWT refresh token")
    public String generateRefreshToken(Long userId, String email) {
        Instant now = Instant.now();
        // Refresh token expires in 7 days
        Instant expiration = now.plusMillis(7 * 24 * 60 * 60 * 1000L);

        return Jwts.builder()
                .subject(userId.toString())
                .claim("email", email)
                .claim("type", "refresh")
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(secretKey, Jwts.SIG.HS512)
                .compact();
    }

    /**
     * Validate JWT token and extract claims
     */
    @Timed(value = "auth.jwt.token.validation.time", description = "Time taken to validate JWT token")
    public JwtTokenInfo validateToken(String token) {
        try {
            // Check if token is blacklisted
            if (isTokenBlacklisted(token)) {
                logger.debug("Token is blacklisted: {}", token.substring(0, Math.min(token.length(), 20)));
                return null;
            }

            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            Long userId = Long.parseLong(claims.getSubject());
            String email = claims.get("email", String.class);
            String type = claims.get("type", String.class);
            Date expiration = claims.getExpiration();

            return new JwtTokenInfo(userId, email, type, 
                    LocalDateTime.ofInstant(expiration.toInstant(), ZoneId.systemDefault()));

        } catch (ExpiredJwtException e) {
            logger.debug("JWT token is expired: {}", e.getMessage());
            return null;
        } catch (UnsupportedJwtException e) {
            logger.warn("JWT token is unsupported: {}", e.getMessage());
            return null;
        } catch (MalformedJwtException e) {
            logger.warn("JWT token is malformed: {}", e.getMessage());
            return null;
        } catch (SecurityException e) {
            logger.warn("JWT signature validation failed: {}", e.getMessage());
            return null;
        } catch (IllegalArgumentException e) {
            logger.warn("JWT token compact of handler are invalid: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.error("Unexpected error during JWT validation: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract user ID from token without full validation (for blacklisting)
     */
    public Long extractUserIdFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            
            return Long.parseLong(claims.getSubject());
        } catch (Exception e) {
            logger.debug("Could not extract user ID from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract email from token
     */
    public String extractEmailFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            
            return claims.get("email", String.class);
        } catch (Exception e) {
            logger.debug("Could not extract email from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Extract expiration time from token
     */
    public LocalDateTime extractExpirationFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            
            Date expiration = claims.getExpiration();
            return LocalDateTime.ofInstant(expiration.toInstant(), ZoneId.systemDefault());
        } catch (Exception e) {
            logger.debug("Could not extract expiration from token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Check if token is valid (not expired and not blacklisted)
     */
    public boolean isTokenValid(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        if (isTokenBlacklisted(token)) {
            return false;
        }
        
        JwtTokenInfo tokenInfo = validateToken(token);
        return tokenInfo != null && !tokenInfo.isExpired();
    }

    /**
     * Blacklist a token (for logout functionality)
     */
    public void blacklistToken(String token) {
        if (token != null && !token.trim().isEmpty()) {
            blacklistedTokens.add(token);
            logger.debug("Token blacklisted successfully");
        }
    }

    /**
     * Check if token is blacklisted
     */
    public boolean isTokenBlacklisted(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        return blacklistedTokens.contains(token);
    }

    /**
     * Refresh an access token using a refresh token
     */
    public String refreshAccessToken(String refreshToken) {
        JwtTokenInfo tokenInfo = validateToken(refreshToken);
        
        if (tokenInfo == null || !"refresh".equals(tokenInfo.getType())) {
            return null;
        }

        // Generate new access token
        return generateToken(tokenInfo.getUserId(), tokenInfo.getEmail());
    }

    /**
     * Get token expiration time
     */
    public LocalDateTime getTokenExpiration(String token) {
        JwtTokenInfo tokenInfo = validateToken(token);
        return tokenInfo != null ? tokenInfo.getExpiresAt() : null;
    }

    /**
     * Check if token is about to expire (within 5 minutes)
     */
    public boolean isTokenNearExpiry(String token) {
        LocalDateTime expiration = getTokenExpiration(token);
        if (expiration == null) {
            return true; // Invalid token is considered expired
        }
        
        return expiration.isBefore(LocalDateTime.now().plusMinutes(5));
    }

    /**
     * Clean up expired tokens from blacklist (should be called periodically)
     */
    public void cleanupExpiredBlacklistedTokens() {
        blacklistedTokens.removeIf(token -> {
            JwtTokenInfo tokenInfo = validateToken(token);
            return tokenInfo == null; // Remove if token is expired or invalid
        });
        
        logger.debug("Cleaned up expired blacklisted tokens. Current blacklist size: {}", blacklistedTokens.size());
    }

    /**
     * JWT Token Information holder
     */
    public static class JwtTokenInfo {
        private final Long userId;
        private final String email;
        private final String type;
        private final LocalDateTime expiresAt;

        public JwtTokenInfo(Long userId, String email, String type, LocalDateTime expiresAt) {
            this.userId = userId;
            this.email = email;
            this.type = type;
            this.expiresAt = expiresAt;
        }

        public Long getUserId() { return userId; }
        public String getEmail() { return email; }
        public String getType() { return type; }
        public LocalDateTime getExpiresAt() { return expiresAt; }

        public boolean isExpired() {
            return expiresAt.isBefore(LocalDateTime.now());
        }
    }
}