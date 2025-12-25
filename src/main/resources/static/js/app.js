/**
 * Main Application JavaScript
 * Handles page-specific authentication logic and UI interactions
 * Requirements: 3.3, 6.2
 */

class App {
    constructor() {
        this.currentPage = this.getCurrentPage();
        this.init();
    }
    
    /**
     * Get current page identifier
     * @returns {string} Page identifier
     */
    getCurrentPage() {
        const path = window.location.pathname;
        
        if (path.includes('/login')) return 'login';
        if (path.includes('/register')) return 'register';
        if (path.includes('/reset-password')) return 'reset-password';
        if (path.includes('/reset-confirm')) return 'reset-confirm';
        if (path.includes('/dashboard')) return 'dashboard';
        
        return 'unknown';
    }
    
    /**
     * Initialize application
     */
    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.onDOMReady());
        } else {
            this.onDOMReady();
        }
    }
    
    /**
     * Handle DOM ready event
     */
    onDOMReady() {
        // Initialize page-specific functionality
        switch (this.currentPage) {
            case 'login':
                this.initLoginPage();
                break;
            case 'register':
                this.initRegisterPage();
                break;
            case 'reset-password':
                this.initResetPasswordPage();
                break;
            case 'reset-confirm':
                this.initResetConfirmPage();
                break;
            case 'dashboard':
                this.initDashboardPage();
                break;
        }
        
        // Initialize common functionality
        this.initCommon();
    }
    
    /**
     * Initialize login page
     */
    initLoginPage() {
        const loginForm = document.querySelector('form[action*="/auth/login"]');
        
        if (loginForm) {
            loginForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.handleLogin(e.target);
            });
        }
        
        // Check if user is already authenticated
        if (window.authManager && window.authManager.isAuthenticated()) {
            window.location.href = '/auth/dashboard';
        }
    }
    
    /**
     * Handle login form submission
     * @param {HTMLFormElement} form - Login form
     */
    async handleLogin(form) {
        const formData = new FormData(form);
        const email = formData.get('username'); // Spring Security uses 'username' field
        const password = formData.get('password');
        const rememberMe = formData.get('remember-me') === 'on';
        
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.innerHTML;
        
        try {
            // Show loading state
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Signing In...';
            
            // Clear previous errors
            this.clearFormErrors(form);
            
            // Attempt login via API
            const response = await window.authAPI.login(email, password, rememberMe);
            
            // Show success message
            window.showNotification('Login successful! Redirecting...', 'success');
            
            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = '/auth/dashboard';
            }, 1000);
            
        } catch (error) {
            console.error('Login error:', error);
            
            let errorMessage = 'Login failed. Please try again.';
            
            if (error.response) {
                switch (error.response.status) {
                    case 401:
                        errorMessage = 'Invalid email or password.';
                        break;
                    case 423:
                        errorMessage = 'Account is temporarily locked due to multiple failed attempts.';
                        break;
                    case 429:
                        errorMessage = 'Too many login attempts. Please try again later.';
                        break;
                    default:
                        if (error.response.data && error.response.data.message) {
                            errorMessage = error.response.data.message;
                        }
                }
            }
            
            this.showFormError(form, errorMessage);
            
        } finally {
            // Restore button state
            submitButton.disabled = false;
            submitButton.innerHTML = originalText;
        }
    }
    
    /**
     * Initialize register page
     */
    initRegisterPage() {
        const registerForm = document.querySelector('form[action*="/auth/register"]');
        
        if (registerForm) {
            registerForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.handleRegister(e.target);
            });
        }
        
        // Check if user is already authenticated
        if (window.authManager && window.authManager.isAuthenticated()) {
            window.location.href = '/auth/dashboard';
        }
    }
    
    /**
     * Handle register form submission
     * @param {HTMLFormElement} form - Register form
     */
    async handleRegister(form) {
        const formData = new FormData(form);
        const userData = {
            email: formData.get('email'),
            password: formData.get('password'),
            confirmPassword: formData.get('confirmPassword')
        };
        
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.innerHTML;
        
        try {
            // Show loading state
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Creating Account...';
            
            // Clear previous errors
            this.clearFormErrors(form);
            
            // Attempt registration via API
            await window.authAPI.register(userData);
            
            // Show success message
            window.showNotification('Registration successful! Please check your email for verification.', 'success');
            
            // Redirect to login
            setTimeout(() => {
                window.location.href = '/auth/login';
            }, 2000);
            
        } catch (error) {
            console.error('Registration error:', error);
            
            let errorMessage = 'Registration failed. Please try again.';
            
            if (error.response && error.response.data) {
                if (error.response.data.message) {
                    errorMessage = error.response.data.message;
                } else if (error.response.data.errors) {
                    // Handle validation errors
                    const errors = error.response.data.errors;
                    this.showValidationErrors(form, errors);
                    return;
                }
            }
            
            this.showFormError(form, errorMessage);
            
        } finally {
            // Restore button state
            submitButton.disabled = false;
            submitButton.innerHTML = originalText;
        }
    }
    
    /**
     * Initialize reset password page
     */
    initResetPasswordPage() {
        const resetForm = document.querySelector('form[action*="/reset-password"]');
        
        if (resetForm) {
            resetForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.handlePasswordReset(e.target);
            });
        }
    }
    
    /**
     * Handle password reset form submission
     * @param {HTMLFormElement} form - Reset form
     */
    async handlePasswordReset(form) {
        const formData = new FormData(form);
        const email = formData.get('email');
        
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.innerHTML;
        
        try {
            // Show loading state
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Sending...';
            
            // Clear previous errors
            this.clearFormErrors(form);
            
            // Request password reset via API
            await window.authAPI.requestPasswordReset(email);
            
            // Show success message
            window.showNotification('If the email address is registered, you will receive password reset instructions.', 'info');
            
            // Redirect to login
            setTimeout(() => {
                window.location.href = '/auth/login';
            }, 3000);
            
        } catch (error) {
            console.error('Password reset error:', error);
            
            let errorMessage = 'Password reset request failed. Please try again.';
            
            if (error.response && error.response.data && error.response.data.message) {
                errorMessage = error.response.data.message;
            }
            
            this.showFormError(form, errorMessage);
            
        } finally {
            // Restore button state
            submitButton.disabled = false;
            submitButton.innerHTML = originalText;
        }
    }
    
    /**
     * Initialize reset confirm page
     */
    initResetConfirmPage() {
        const confirmForm = document.querySelector('form[action*="/reset-confirm"]');
        
        if (confirmForm) {
            confirmForm.addEventListener('submit', async (e) => {
                e.preventDefault();
                await this.handlePasswordResetConfirm(e.target);
            });
        }
    }
    
    /**
     * Handle password reset confirmation
     * @param {HTMLFormElement} form - Confirm form
     */
    async handlePasswordResetConfirm(form) {
        const formData = new FormData(form);
        const token = formData.get('token') || new URLSearchParams(window.location.search).get('token');
        const newPassword = formData.get('newPassword');
        
        const submitButton = form.querySelector('button[type="submit"]');
        const originalText = submitButton.innerHTML;
        
        try {
            // Show loading state
            submitButton.disabled = true;
            submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Resetting Password...';
            
            // Clear previous errors
            this.clearFormErrors(form);
            
            // Confirm password reset via API
            await window.authAPI.confirmPasswordReset(token, newPassword);
            
            // Show success message
            window.showNotification('Password has been reset successfully! You can now log in.', 'success');
            
            // Redirect to login
            setTimeout(() => {
                window.location.href = '/auth/login';
            }, 2000);
            
        } catch (error) {
            console.error('Password reset confirmation error:', error);
            
            let errorMessage = 'Password reset failed. The token may be invalid or expired.';
            
            if (error.response && error.response.data && error.response.data.message) {
                errorMessage = error.response.data.message;
            }
            
            this.showFormError(form, errorMessage);
            
        } finally {
            // Restore button state
            submitButton.disabled = false;
            submitButton.innerHTML = originalText;
        }
    }
    
    /**
     * Initialize dashboard page
     */
    initDashboardPage() {
        // Check authentication
        if (window.authManager && !window.authManager.isAuthenticated()) {
            window.location.href = '/auth/login';
            return;
        }
        
        // Set up logout handlers
        const logoutButtons = document.querySelectorAll('button[type="submit"]');
        logoutButtons.forEach(button => {
            const form = button.closest('form');
            if (form && form.action.includes('/logout')) {
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    await this.handleLogout();
                });
            }
        });
        
        // Set up other dashboard functionality
        this.initDashboardFeatures();
    }
    
    /**
     * Initialize dashboard features
     */
    initDashboardFeatures() {
        // Update user info display
        if (window.authManager) {
            const userInfo = window.authManager.getUserInfo();
            if (userInfo) {
                // Update user email displays
                const emailElements = document.querySelectorAll('[sec\\:authentication="name"]');
                emailElements.forEach(el => {
                    if (userInfo.email) {
                        el.textContent = userInfo.email;
                    }
                });
            }
        }
        
        // Set up periodic session validation
        this.startSessionValidation();
    }
    
    /**
     * Start periodic session validation for dashboard
     */
    startSessionValidation() {
        // Validate session every 10 minutes when on dashboard
        setInterval(async () => {
            if (window.authManager) {
                await window.authManager.validateCurrentToken();
            }
        }, 10 * 60 * 1000);
    }
    
    /**
     * Handle logout
     */
    async handleLogout() {
        try {
            if (window.authManager) {
                await window.authManager.logout();
            }
        } catch (error) {
            console.error('Logout error:', error);
            // Force logout even if server call fails
            if (window.authManager) {
                await window.authManager.handleLogout(false);
            }
        }
    }
    
    /**
     * Initialize common functionality
     */
    initCommon() {
        // Set up auth manager logout callback
        if (window.authManager) {
            window.authManager.onLogout(() => {
                console.log('User logged out');
            });
        }
        
        // Set up CSRF token meta tags for API calls
        this.setupCSRFTokens();
    }
    
    /**
     * Set up CSRF tokens for API calls
     */
    setupCSRFTokens() {
        const csrfToken = document.querySelector('input[name="_csrf"]');
        const csrfHeader = '_csrf';
        
        if (csrfToken) {
            // Create meta tags for CSRF token
            let csrfMeta = document.querySelector('meta[name="_csrf"]');
            if (!csrfMeta) {
                csrfMeta = document.createElement('meta');
                csrfMeta.name = '_csrf';
                document.head.appendChild(csrfMeta);
            }
            csrfMeta.content = csrfToken.value;
            
            let csrfHeaderMeta = document.querySelector('meta[name="_csrf_header"]');
            if (!csrfHeaderMeta) {
                csrfHeaderMeta = document.createElement('meta');
                csrfHeaderMeta.name = '_csrf_header';
                document.head.appendChild(csrfHeaderMeta);
            }
            csrfHeaderMeta.content = csrfHeader;
        }
    }
    
    /**
     * Clear form errors
     * @param {HTMLFormElement} form - Form element
     */
    clearFormErrors(form) {
        // Remove existing error alerts
        const alerts = form.querySelectorAll('.alert-danger');
        alerts.forEach(alert => alert.remove());
        
        // Remove field-specific errors
        const invalidFields = form.querySelectorAll('.is-invalid');
        invalidFields.forEach(field => field.classList.remove('is-invalid'));
        
        const feedbacks = form.querySelectorAll('.invalid-feedback');
        feedbacks.forEach(feedback => feedback.remove());
    }
    
    /**
     * Show form error
     * @param {HTMLFormElement} form - Form element
     * @param {string} message - Error message
     */
    showFormError(form, message) {
        const errorAlert = document.createElement('div');
        errorAlert.className = 'alert alert-danger';
        errorAlert.innerHTML = `<i class="fas fa-exclamation-triangle me-2"></i>${message}`;
        
        // Insert at the beginning of the form
        form.insertBefore(errorAlert, form.firstChild);
    }
    
    /**
     * Show validation errors
     * @param {HTMLFormElement} form - Form element
     * @param {Object} errors - Validation errors
     */
    showValidationErrors(form, errors) {
        Object.keys(errors).forEach(fieldName => {
            const field = form.querySelector(`[name="${fieldName}"]`);
            if (field) {
                field.classList.add('is-invalid');
                
                const feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                feedback.textContent = errors[fieldName];
                
                field.parentNode.appendChild(feedback);
            }
        });
    }
}

// Initialize application when script loads
window.app = new App();

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = App;
}