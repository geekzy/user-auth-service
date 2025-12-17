package com.example.userauthentication.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {
    
    private Jwt jwt = new Jwt();
    private Password password = new Password();
    private RateLimit rateLimit = new RateLimit();
    private AccountLock accountLock = new AccountLock();
    
    public static class Jwt {
        private String secret;
        private long expiration;
        
        public String getSecret() { return secret; }
        public void setSecret(String secret) { this.secret = secret; }
        public long getExpiration() { return expiration; }
        public void setExpiration(long expiration) { this.expiration = expiration; }
    }
    
    public static class Password {
        private Bcrypt bcrypt = new Bcrypt();
        
        public static class Bcrypt {
            private int rounds;
            
            public int getRounds() { return rounds; }
            public void setRounds(int rounds) { this.rounds = rounds; }
        }
        
        public Bcrypt getBcrypt() { return bcrypt; }
        public void setBcrypt(Bcrypt bcrypt) { this.bcrypt = bcrypt; }
    }
    
    public static class RateLimit {
        private int maxAttempts;
        private int windowMinutes;
        
        public int getMaxAttempts() { return maxAttempts; }
        public void setMaxAttempts(int maxAttempts) { this.maxAttempts = maxAttempts; }
        public int getWindowMinutes() { return windowMinutes; }
        public void setWindowMinutes(int windowMinutes) { this.windowMinutes = windowMinutes; }
    }
    
    public static class AccountLock {
        private int durationMinutes;
        
        public int getDurationMinutes() { return durationMinutes; }
        public void setDurationMinutes(int durationMinutes) { this.durationMinutes = durationMinutes; }
    }
    
    public Jwt getJwt() { return jwt; }
    public void setJwt(Jwt jwt) { this.jwt = jwt; }
    public Password getPassword() { return password; }
    public void setPassword(Password password) { this.password = password; }
    public RateLimit getRateLimit() { return rateLimit; }
    public void setRateLimit(RateLimit rateLimit) { this.rateLimit = rateLimit; }
    public AccountLock getAccountLock() { return accountLock; }
    public void setAccountLock(AccountLock accountLock) { this.accountLock = accountLock; }
}