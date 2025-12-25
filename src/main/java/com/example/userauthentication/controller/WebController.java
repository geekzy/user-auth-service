package com.example.userauthentication.controller;

import com.example.userauthentication.dto.*;
import com.example.userauthentication.exception.InvalidPasswordException;
import com.example.userauthentication.exception.UserAlreadyExistsException;
import com.example.userauthentication.service.AuthenticationService;
import com.example.userauthentication.service.PasswordResetService;
import com.example.userauthentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Web controller for authentication pages using Thymeleaf templates.
 * Provides web interface for user registration, login, and password reset.
 * 
 * Requirements: 1.1, 1.3, 1.4, 2.1, 2.2, 4.1, 4.3, 4.4, 6.3
 */
@Controller
@RequestMapping("/auth")
public class WebController {

    private static final Logger logger = LoggerFactory.getLogger(WebController.class);

    private final UserService userService;
    private final AuthenticationService authenticationService;
    private final PasswordResetService passwordResetService;

    public WebController(UserService userService,
                        AuthenticationService authenticationService,
                        PasswordResetService passwordResetService) {
        this.userService = userService;
        this.authenticationService = authenticationService;
        this.passwordResetService = passwordResetService;
    }

    /**
     * Display registration page.
     * 
     * Requirements: 1.1, 1.3, 1.4
     */
    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("userRegistrationRequest", new UserRegistrationRequest());
        return "auth/register";
    }
    /**
     * Process registration form submission.
     * 
     * Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
     */
    @PostMapping("/register")
    public String processRegistration(@Valid @ModelAttribute UserRegistrationRequest request,
                                    BindingResult bindingResult,
                                    Model model,
                                    RedirectAttributes redirectAttributes,
                                    HttpServletRequest httpRequest) {
        try {
            logger.info("Web registration request received for email: {} from IP: {}", 
                       request.getEmail(), getClientIpAddress(httpRequest));
            
            // Check for validation errors
            if (bindingResult.hasErrors()) {
                model.addAttribute("userRegistrationRequest", request);
                return "auth/register";
            }
            
            // Additional password confirmation check
            if (!request.isPasswordConfirmed()) {
                bindingResult.rejectValue("confirmPassword", "password.mismatch", 
                                        "Password and confirmation password do not match");
                model.addAttribute("userRegistrationRequest", request);
                return "auth/register";
            }
            
            // Register user
            UserRegistrationResponse response = userService.registerUser(request);
            
            logger.info("Web registration successful for email: {} with user ID: {}", 
                       response.getEmail(), response.getId());
            
            redirectAttributes.addFlashAttribute("successMessage", 
                "Registration successful! You can now log in.");
            
            return "redirect:/auth/login";
            
        } catch (UserAlreadyExistsException e) {
            logger.warn("Web registration failed - user already exists: {}", e.getMessage());
            bindingResult.rejectValue("email", "email.exists", e.getMessage());
            model.addAttribute("userRegistrationRequest", request);
            return "auth/register";
        } catch (InvalidPasswordException e) {
            logger.warn("Web registration failed - invalid password: {}", e.getMessage());
            bindingResult.rejectValue("password", "password.invalid", e.getMessage());
            model.addAttribute("userRegistrationRequest", request);
            return "auth/register";
        } catch (Exception e) {
            logger.error("Unexpected error during web registration for email: {}", request.getEmail(), e);
            model.addAttribute("errorMessage", "Registration failed due to an internal error");
            model.addAttribute("userRegistrationRequest", request);
            return "auth/register";
        }
    }

    /**
     * Display login page.
     * 
     * Requirements: 2.1, 2.2, 6.3
     */
    @GetMapping("/login")
    public String showLoginForm(Model model) {
        model.addAttribute("loginRequest", new LoginRequest());
        return "auth/login";
    }

    /**
     * Handle login form submission.
     * This is handled by Spring Security, but we can add custom logic here if needed.
     */
    @PostMapping("/login")
    public String processLogin() {
        // This method won't be called directly as Spring Security intercepts the POST
        // But having it here ensures proper mapping and can be used for custom logic
        return "redirect:/auth/dashboard";
    }
    /**
     * Display password reset request page.
     * 
     * Requirements: 4.1
     */
    @GetMapping("/reset-password")
    public String showPasswordResetForm(Model model) {
        model.addAttribute("passwordResetRequest", new PasswordResetRequest());
        return "auth/reset-password";
    }

    /**
     * Process password reset request.
     * 
     * Requirements: 4.1, 4.2
     */
    @PostMapping("/reset-password")
    public String processPasswordReset(@Valid @ModelAttribute PasswordResetRequest request,
                                     BindingResult bindingResult,
                                     Model model,
                                     RedirectAttributes redirectAttributes) {
        try {
            logger.info("Web password reset request received for email: {}", request.getEmail());
            
            if (bindingResult.hasErrors()) {
                model.addAttribute("passwordResetRequest", request);
                return "auth/reset-password";
            }
            
            passwordResetService.requestPasswordReset(request.getEmail());
            
            redirectAttributes.addFlashAttribute("successMessage", 
                "If the email address is registered, you will receive password reset instructions");
            
            return "redirect:/auth/login";
            
        } catch (Exception e) {
            logger.error("Unexpected error during web password reset request for email: {}", request.getEmail(), e);
            model.addAttribute("errorMessage", "Password reset request failed due to an internal error");
            model.addAttribute("passwordResetRequest", request);
            return "auth/reset-password";
        }
    }

    /**
     * Display password reset confirmation page.
     * 
     * Requirements: 4.3, 4.4
     */
    @GetMapping("/reset-confirm")
    public String showPasswordResetConfirmForm(@RequestParam String token, Model model) {
        model.addAttribute("passwordResetConfirmRequest", new PasswordResetConfirmRequest());
        model.addAttribute("token", token);
        return "auth/reset-confirm";
    }
    /**
     * Process password reset confirmation.
     * 
     * Requirements: 4.4, 4.5
     */
    @PostMapping("/reset-confirm")
    public String processPasswordResetConfirm(@Valid @ModelAttribute PasswordResetConfirmRequest request,
                                            BindingResult bindingResult,
                                            @RequestParam String token,
                                            Model model,
                                            RedirectAttributes redirectAttributes) {
        try {
            logger.info("Web password reset confirmation request received");
            
            if (bindingResult.hasErrors()) {
                model.addAttribute("passwordResetConfirmRequest", request);
                model.addAttribute("token", token);
                return "auth/reset-confirm";
            }
            
            // Additional password confirmation check
            if (!request.isPasswordConfirmed()) {
                bindingResult.rejectValue("confirmPassword", "password.mismatch", 
                                        "New password and confirmation password do not match");
                model.addAttribute("passwordResetConfirmRequest", request);
                model.addAttribute("token", token);
                return "auth/reset-confirm";
            }
            
            // Set token in request
            request.setToken(token);
            
            boolean success = passwordResetService.completePasswordReset(request.getToken(), request.getNewPassword());
            
            if (success) {
                logger.info("Web password reset completed successfully");
                redirectAttributes.addFlashAttribute("successMessage", 
                    "Password has been reset successfully. You can now log in with your new password.");
                return "redirect:/auth/login";
            } else {
                logger.warn("Web password reset completion failed");
                model.addAttribute("errorMessage", "Password reset failed. The token may be invalid or expired.");
                model.addAttribute("passwordResetConfirmRequest", request);
                model.addAttribute("token", token);
                return "auth/reset-confirm";
            }
            
        } catch (Exception e) {
            logger.error("Unexpected error during web password reset confirmation", e);
            model.addAttribute("errorMessage", "Password reset failed due to an internal error");
            model.addAttribute("passwordResetConfirmRequest", request);
            model.addAttribute("token", token);
            return "auth/reset-confirm";
        }
    }
    /**
     * Dashboard page (protected).
     */
    @GetMapping("/dashboard")
    public String showDashboard(Model model) {
        return "auth/dashboard";
    }

    /**
     * Extracts the client's IP address from the HTTP request.
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty() && !"unknown".equalsIgnoreCase(xForwardedFor)) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty() && !"unknown".equalsIgnoreCase(xRealIp)) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}