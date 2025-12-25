/**
 * API Configuration with Axios Interceptors
 * Handles automatic JWT token attachment and response handling
 * Requirements: 3.3, 6.2
 */

// Create axios instance with base configuration
const api = axios.create({
    baseURL: '/api',
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json'
    }
});

/**
 * Request interceptor to add authentication token
 */
api.interceptors.request.use(
    (config) => {
        // Skip auth headers for public endpoints
        const publicEndpoints = ['/auth/login', '/auth/register', '/auth/reset-request', '/auth/reset-confirm'];
        const isPublicEndpoint = publicEndpoints.some(endpoint => config.url.includes(endpoint));
        
        // Add authentication token if available and not a public endpoint
        if (!isPublicEndpoint && window.authManager) {
            const authHeader = window.authManager.getAuthHeader();
            if (authHeader) {
                config.headers.Authorization = authHeader;
            }
        }
        
        // Add CSRF token for non-GET requests
        if (config.method !== 'get') {
            const csrfToken = document.querySelector('meta[name="_csrf"]');
            const csrfHeader = document.querySelector('meta[name="_csrf_header"]');
            
            if (csrfToken && csrfHeader) {
                config.headers[csrfHeader.getAttribute('content')] = csrfToken.getAttribute('content');
            }
        }
        
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

/**
 * Response interceptor to handle authentication errors
 */
api.interceptors.response.use(
    (response) => {
        // Handle successful responses
        return response;
    },
    async (error) => {
        const originalRequest = error.config;
        
        // Handle 401 Unauthorized responses
        if (error.response && error.response.status === 401) {
            // Avoid infinite loops
            if (originalRequest._retry) {
                if (window.authManager) {
                    await window.authManager.handleLogout(false);
                }
                return Promise.reject(error);
            }
            
            originalRequest._retry = true;
            
            // Try to refresh token
            if (window.authManager) {
                try {
                    await window.authManager.refreshAuthToken();
                    
                    // Retry original request with new token
                    const authHeader = window.authManager.getAuthHeader();
                    if (authHeader) {
                        originalRequest.headers.Authorization = authHeader;
                    }
                    
                    return api(originalRequest);
                } catch (refreshError) {
                    // Refresh failed, logout user
                    await window.authManager.handleLogout(false);
                    return Promise.reject(error);
                }
            }
        }
        
        // Handle 403 Forbidden responses
        if (error.response && error.response.status === 403) {
            console.warn('Access forbidden:', error.response.data);
            
            // Show user-friendly message
            showNotification('Access denied. You may not have permission for this action.', 'error');
        }
        
        // Handle network errors
        if (!error.response) {
            console.error('Network error:', error.message);
            showNotification('Network error. Please check your connection.', 'error');
        }
        
        return Promise.reject(error);
    }
);

/**
 * Authentication API methods
 */
const authAPI = {
    /**
     * Login user
     * @param {string} email - User email
     * @param {string} password - User password
     * @param {boolean} rememberMe - Remember me option
     * @returns {Promise} Login response
     */
    async login(email, password, rememberMe = false) {
        const response = await api.post('/auth/login', {
            email,
            password,
            rememberMe
        });
        
        // Store token and user info
        if (response.data.token && window.authManager) {
            window.authManager.setToken(
                response.data.token,
                response.data.user,
                response.data.refreshToken
            );
        }
        
        return response.data;
    },
    
    /**
     * Logout user
     * @returns {Promise} Logout response
     */
    async logout() {
        if (window.authManager) {
            await window.authManager.logout();
        }
    },
    
    /**
     * Register new user
     * @param {Object} userData - User registration data
     * @returns {Promise} Registration response
     */
    async register(userData) {
        const response = await api.post('/auth/register', userData);
        return response.data;
    },
    
    /**
     * Request password reset
     * @param {string} email - User email
     * @returns {Promise} Reset request response
     */
    async requestPasswordReset(email) {
        const response = await api.post('/auth/reset-request', { email });
        return response.data;
    },
    
    /**
     * Confirm password reset
     * @param {string} token - Reset token
     * @param {string} newPassword - New password
     * @returns {Promise} Reset confirmation response
     */
    async confirmPasswordReset(token, newPassword) {
        const response = await api.post('/auth/reset-confirm', {
            token,
            newPassword
        });
        return response.data;
    },
    
    /**
     * Validate current session
     * @returns {Promise} Session validation response
     */
    async validateSession() {
        const response = await api.get('/auth/session');
        return response.data;
    }
};

/**
 * Show notification to user
 * @param {string} message - Notification message
 * @param {string} type - Notification type (success, error, warning, info)
 */
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type} alert-dismissible fade show position-fixed`;
    notification.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
    
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    // Add to page
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}

/**
 * Initialize API configuration
 */
function initializeAPI() {
    // Set up global error handler
    window.addEventListener('unhandledrejection', (event) => {
        if (event.reason && event.reason.response) {
            const error = event.reason.response;
            
            // Don't show notifications for handled auth errors
            if (error.status === 401) {
                return;
            }
            
            // Show generic error message for unhandled API errors
            if (error.status >= 500) {
                showNotification('Server error. Please try again later.', 'error');
            }
        }
    });
}

// Initialize when DOM is loaded
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeAPI);
} else {
    initializeAPI();
}

// Export API instance and methods
window.api = api;
window.authAPI = authAPI;
window.showNotification = showNotification;

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { api, authAPI, showNotification };
}