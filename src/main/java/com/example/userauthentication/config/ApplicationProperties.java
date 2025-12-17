package com.example.userauthentication.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app")
public class ApplicationProperties {
    
    private Email email = new Email();
    private Session session = new Session();
    private PasswordReset passwordReset = new PasswordReset();
    
    public static class Email {
        private String from;
        
        public String getFrom() { return from; }
        public void setFrom(String from) { this.from = from; }
    }
    
    public static class Session {
        private int timeoutMinutes;
        private boolean extendOnActivity;
        private int rememberMeDurationDays;
        
        public int getTimeoutMinutes() { return timeoutMinutes; }
        public void setTimeoutMinutes(int timeoutMinutes) { this.timeoutMinutes = timeoutMinutes; }
        public boolean isExtendOnActivity() { return extendOnActivity; }
        public void setExtendOnActivity(boolean extendOnActivity) { this.extendOnActivity = extendOnActivity; }
        public int getRememberMeDurationDays() { return rememberMeDurationDays; }
        public void setRememberMeDurationDays(int rememberMeDurationDays) { this.rememberMeDurationDays = rememberMeDurationDays; }
    }
    
    public static class PasswordReset {
        private int tokenExpirationMinutes;
        private String baseUrl;
        
        public int getTokenExpirationMinutes() { return tokenExpirationMinutes; }
        public void setTokenExpirationMinutes(int tokenExpirationMinutes) { this.tokenExpirationMinutes = tokenExpirationMinutes; }
        public String getBaseUrl() { return baseUrl; }
        public void setBaseUrl(String baseUrl) { this.baseUrl = baseUrl; }
    }
    
    public Email getEmail() { return email; }
    public void setEmail(Email email) { this.email = email; }
    public Session getSession() { return session; }
    public void setSession(Session session) { this.session = session; }
    public PasswordReset getPasswordReset() { return passwordReset; }
    public void setPasswordReset(PasswordReset passwordReset) { this.passwordReset = passwordReset; }
}