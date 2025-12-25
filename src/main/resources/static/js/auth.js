/**
 * Authentication State Management
 * Handles JWT token storage, validation, and automatic logout
 * Requirements: 3.3, 6.2
 */

class AuthManager {
    constructor() {
        this.tokenKey = 'auth_token';
        this.refreshTokenKey = 'refresh_token';
        this.userKey = 'user_info';
        this.tokenCheckInterval = null;
        this.logoutCallbacks = [];
        
        // Initialize authentication state
        this.init();
    }
    
    /**
     * Initialize authentication manager
     */
    init() {
        // Check token validity on page load
        this.validateCurrentToken();
        
        // Set up periodic token validation
        this.startTokenValidation();
        
        // Listen for storage changes (multi-tab logout)
        window.addEventListener('storage', (e) => {
            if (e.key === this.tokenKey && !e.newValue) {
                this.handleLogout(false);
            }
        });
        
        // Listen for page visibility changes to validate token
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.validateCurrentToken();
            }
        });
    }
    
    /**
     * Store authentication token and user info
     * @param {string} token - JWT token
     * @param {Object} userInfo - User information
     * @param {string} refreshToken - Refresh token (optional)
     */
    setToken(token, userInfo = null, refreshToken = null) {
        if (token) {
            localStorage.setItem(this.tokenKey, token);
            
            if (userInfo) {
                localStorage.setItem(this.userKey, JSON.stringify(userInfo));
            }
            
            if (refreshToken) {
                localStorage.setItem(this.refreshTokenKey, refreshToken);
            }
            
            // Start token validation
            this.startTokenValidation();
        }
    }
    
    /**
     * Get stored authentication token
     * @returns {string|null} JWT token
     */
    getToken() {
        return localStorage.getItem(this.tokenKey);
    }
    
    /**
     * Get stored user information
     * @returns {Object|null} User information
     */
    getUserInfo() {
        const userInfo = localStorage.getItem(this.userKey);
        return userInfo ? JSON.parse(userInfo) : null;
    }
    
    /**
     * Get refresh token
     * @returns {string|null} Refresh token
     */
    getRefreshToken() {
        return localStorage.getItem(this.refreshTokenKey);
    }
    
    /**
     * Check if user is authenticated
     * @returns {boolean} Authentication status
     */
    isAuthenticated() {
        const token = this.getToken();
        return token && !this.isTokenExpired(token);
    }
    
    /**
     * Check if token is expired
     * @param {string} token - JWT token
     * @returns {boolean} True if expired
     */
    isTokenExpired(token) {
        if (!token) return true;
        
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            const currentTime = Math.floor(Date.now() / 1000);
            
            // Check if token expires within next 5 minutes (300 seconds)
            return payload.exp && payload.exp < (currentTime + 300);
        } catch (error) {
            console.error('Error parsing token:', error);
            return true;
        }
    }
    
    /**
     * Get token expiration time
     * @param {string} token - JWT token
     * @returns {Date|null} Expiration date
     */
    getTokenExpiration(token) {
        if (!token) return null;
        
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            return payload.exp ? new Date(payload.exp * 1000) : null;
        } catch (error) {
            console.error('Error parsing token expiration:', error);
            return null;
        }
    }
    
    /**
     * Validate current token and handle expiration
     */
    async validateCurrentToken() {
        const token = this.getToken();
        
        if (!token) {
            return;
        }
        
        if (this.isTokenExpired(token)) {
            console.log('Token expired, attempting refresh or logout');
            await this.handleTokenExpiration();
            return;
        }
        
        // Validate token with server
        try {
            const response = await fetch('/api/auth/session', {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                console.log('Token validation failed with server');
                await this.handleTokenExpiration();
            }
        } catch (error) {
            console.error('Error validating token with server:', error);
            // Don't logout on network errors, just log
        }
    }
    
    /**
     * Handle token expiration
     */
    async handleTokenExpiration() {
        const refreshToken = this.getRefreshToken();
        
        if (refreshToken) {
            try {
                await this.refreshAuthToken();
                return;
            } catch (error) {
                console.error('Token refresh failed:', error);
            }
        }
        
        // If refresh fails or no refresh token, logout
        this.handleLogout(true);
    }
    
    /**
     * Refresh authentication token
     */
    async refreshAuthToken() {
        const refreshToken = this.getRefreshToken();
        
        if (!refreshToken) {
            throw new Error('No refresh token available');
        }
        
        const response = await fetch('/api/auth/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ refreshToken })
        });
        
        if (!response.ok) {
            throw new Error('Token refresh failed');
        }
        
        const data = await response.json();
        this.setToken(data.token, data.user, data.refreshToken);
    }
    
    /**
     * Start periodic token validation
     */
    startTokenValidation() {
        // Clear existing interval
        if (this.tokenCheckInterval) {
            clearInterval(this.tokenCheckInterval);
        }
        
        // Check token every 5 minutes
        this.tokenCheckInterval = setInterval(() => {
            this.validateCurrentToken();
        }, 5 * 60 * 1000);
    }
    
    /**
     * Stop token validation
     */
    stopTokenValidation() {
        if (this.tokenCheckInterval) {
            clearInterval(this.tokenCheckInterval);
            this.tokenCheckInterval = null;
        }
    }
    
    /**
     * Handle logout
     * @param {boolean} callServer - Whether to call server logout endpoint
     */
    async handleLogout(callServer = true) {
        const token = this.getToken();
        
        // Call server logout if requested and token exists
        if (callServer && token) {
            try {
                await fetch('/api/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                        'Content-Type': 'application/json'
                    }
                });
            } catch (error) {
                console.error('Error calling server logout:', error);
            }
        }
        
        // Clear local storage
        localStorage.removeItem(this.tokenKey);
        localStorage.removeItem(this.refreshTokenKey);
        localStorage.removeItem(this.userKey);
        
        // Stop token validation
        this.stopTokenValidation();
        
        // Execute logout callbacks
        this.logoutCallbacks.forEach(callback => {
            try {
                callback();
            } catch (error) {
                console.error('Error executing logout callback:', error);
            }
        });
        
        // Redirect to login page
        if (window.location.pathname !== '/auth/login') {
            window.location.href = '/auth/login?logout=true';
        }
    }
    
    /**
     * Add logout callback
     * @param {Function} callback - Function to call on logout
     */
    onLogout(callback) {
        if (typeof callback === 'function') {
            this.logoutCallbacks.push(callback);
        }
    }
    
    /**
     * Manual logout
     */
    async logout() {
        await this.handleLogout(true);
    }
    
    /**
     * Get authorization header value
     * @returns {string|null} Authorization header value
     */
    getAuthHeader() {
        const token = this.getToken();
        return token ? `Bearer ${token}` : null;
    }
}

// Create global auth manager instance
window.authManager = new AuthManager();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = AuthManager;
}