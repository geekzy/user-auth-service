package com.example.userauthentication.service;

import com.example.userauthentication.model.User;
import com.example.userauthentication.repository.UserRepository;
import io.micrometer.core.annotation.Timed;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for detecting new devices and sending security notifications.
 * Implements device fingerprinting and detection logic with async security 
 * notification email sending and device tracking with privacy considerations.
 * 
 * Requirements: 6.5
 */
@Service
public class DeviceDetectionService {

    private static final Logger logger = LoggerFactory.getLogger(DeviceDetectionService.class);
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    
    // In-memory storage for known devices (in production, use Redis or database)
    // Key: userId, Value: Set of device fingerprints
    private final Map<Long, Set<String>> knownDevices = new ConcurrentHashMap<>();
    
    private final EmailService emailService;
    private final UserRepository userRepository;
    
    // Performance monitoring metrics
    private final Counter deviceDetectionAttempts;
    private final Counter newDeviceDetections;
    private final Counter knownDeviceLogins;
    private final Counter deviceNotificationsSent;
    private final Counter deviceNotificationFailures;

    public DeviceDetectionService(EmailService emailService,
                                UserRepository userRepository,
                                MeterRegistry meterRegistry) {
        this.emailService = emailService;
        this.userRepository = userRepository;
        
        // Initialize performance metrics
        this.deviceDetectionAttempts = Counter.builder("auth.device.detection.attempts")
                .description("Total number of device detection attempts")
                .register(meterRegistry);
        this.newDeviceDetections = Counter.builder("auth.device.new.detections")
                .description("Total number of new device detections")
                .register(meterRegistry);
        this.knownDeviceLogins = Counter.builder("auth.device.known.logins")
                .description("Total number of logins from known devices")
                .register(meterRegistry);
        this.deviceNotificationsSent = Counter.builder("auth.device.notifications.sent")
                .description("Total number of device notification emails sent")
                .register(meterRegistry);
        this.deviceNotificationFailures = Counter.builder("auth.device.notifications.failures")
                .description("Total number of failed device notification attempts")
                .register(meterRegistry);
    }

    /**
     * Detects if a login is from a new device and sends notification if needed.
     * 
     * @param userId the user ID
     * @param userAgent the browser user agent string
     * @param ipAddress the client IP address
     * @param loginTime the time of login
     * @return DeviceDetectionResult containing detection status and device info
     */
    @Timed(value = "auth.device.detection.processing.time", description = "Time taken to process device detection")
    public DeviceDetectionResult detectAndNotify(Long userId, String userAgent, String ipAddress, LocalDateTime loginTime) {
        deviceDetectionAttempts.increment();
        
        try {
            if (userId == null) {
                logger.warn("Device detection called with null user ID");
                return DeviceDetectionResult.error("Invalid user ID");
            }
            
            // Generate device fingerprint
            String deviceFingerprint = generateDeviceFingerprint(userAgent, ipAddress);
            
            // Check if this is a known device
            boolean isKnownDevice = isKnownDevice(userId, deviceFingerprint);
            
            if (isKnownDevice) {
                knownDeviceLogins.increment();
                logger.debug("Login from known device for user ID: {}", userId);
                return DeviceDetectionResult.knownDevice(deviceFingerprint);
            } else {
                newDeviceDetections.increment();
                logger.info("New device detected for user ID: {} with fingerprint: {}", userId, deviceFingerprint);
                
                // Register the new device
                registerNewDevice(userId, deviceFingerprint);
                
                // Send async security notification
                sendNewDeviceNotificationAsync(userId, userAgent, ipAddress, loginTime);
                
                return DeviceDetectionResult.newDevice(deviceFingerprint, generateDeviceInfo(userAgent, ipAddress));
            }
            
        } catch (Exception e) {
            logger.error("Error during device detection for user ID: {}", userId, e);
            return DeviceDetectionResult.error("Device detection failed");
        }
    }

    /**
     * Generates a device fingerprint based on user agent and IP address.
     * Uses privacy-conscious approach by hashing sensitive information.
     * 
     * @param userAgent the browser user agent string
     * @param ipAddress the client IP address
     * @return a unique device fingerprint
     */
    private String generateDeviceFingerprint(String userAgent, String ipAddress) {
        try {
            // Extract key components for fingerprinting while preserving privacy
            String browserInfo = extractBrowserInfo(userAgent);
            String osInfo = extractOSInfo(userAgent);
            String ipSubnet = maskIpAddress(ipAddress); // Use subnet instead of full IP for privacy
            
            // Combine components
            String fingerprintData = String.format("%s|%s|%s", browserInfo, osInfo, ipSubnet);
            
            // Hash the fingerprint for privacy and consistency
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(fingerprintData.getBytes());
            
            // Convert to hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            
            return hexString.toString();
            
        } catch (NoSuchAlgorithmException e) {
            logger.error("SHA-256 algorithm not available for device fingerprinting", e);
            // Fallback to simple hash
            return String.valueOf((userAgent + ipAddress).hashCode());
        }
    }

    /**
     * Extracts browser information from user agent string.
     * 
     * @param userAgent the user agent string
     * @return simplified browser information
     */
    private String extractBrowserInfo(String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return "unknown";
        }
        
        String lowerUserAgent = userAgent.toLowerCase();
        
        if (lowerUserAgent.contains("chrome")) {
            return "chrome";
        } else if (lowerUserAgent.contains("firefox")) {
            return "firefox";
        } else if (lowerUserAgent.contains("safari") && !lowerUserAgent.contains("chrome")) {
            return "safari";
        } else if (lowerUserAgent.contains("edge")) {
            return "edge";
        } else if (lowerUserAgent.contains("opera")) {
            return "opera";
        } else {
            return "other";
        }
    }

    /**
     * Extracts operating system information from user agent string.
     * 
     * @param userAgent the user agent string
     * @return simplified OS information
     */
    private String extractOSInfo(String userAgent) {
        if (!StringUtils.hasText(userAgent)) {
            return "unknown";
        }
        
        String lowerUserAgent = userAgent.toLowerCase();
        
        if (lowerUserAgent.contains("windows")) {
            return "windows";
        } else if (lowerUserAgent.contains("mac os") || lowerUserAgent.contains("macos")) {
            return "macos";
        } else if (lowerUserAgent.contains("linux")) {
            return "linux";
        } else if (lowerUserAgent.contains("android")) {
            return "android";
        } else if (lowerUserAgent.contains("iphone") || lowerUserAgent.contains("ipad")) {
            return "ios";
        } else {
            return "other";
        }
    }

    /**
     * Masks IP address for privacy by keeping only the subnet.
     * 
     * @param ipAddress the full IP address
     * @return masked IP address (subnet only)
     */
    private String maskIpAddress(String ipAddress) {
        if (!StringUtils.hasText(ipAddress)) {
            return "unknown";
        }
        
        // For IPv4, keep first 3 octets (e.g., 192.168.1.x becomes 192.168.1.0)
        if (ipAddress.contains(".")) {
            String[] parts = ipAddress.split("\\.");
            if (parts.length == 4) {
                return String.format("%s.%s.%s.0", parts[0], parts[1], parts[2]);
            }
        }
        
        // For IPv6 or other formats, use a simplified approach
        return "subnet_" + Math.abs(ipAddress.hashCode() % 10000);
    }

    /**
     * Checks if a device fingerprint is known for a user.
     * 
     * @param userId the user ID
     * @param deviceFingerprint the device fingerprint
     * @return true if the device is known
     */
    private boolean isKnownDevice(Long userId, String deviceFingerprint) {
        Set<String> userDevices = knownDevices.get(userId);
        return userDevices != null && userDevices.contains(deviceFingerprint);
    }

    /**
     * Registers a new device for a user.
     * 
     * @param userId the user ID
     * @param deviceFingerprint the device fingerprint to register
     */
    private void registerNewDevice(Long userId, String deviceFingerprint) {
        knownDevices.computeIfAbsent(userId, k -> ConcurrentHashMap.newKeySet()).add(deviceFingerprint);
        logger.debug("Registered new device for user ID: {} with fingerprint: {}", userId, deviceFingerprint);
    }

    /**
     * Generates human-readable device information for notifications.
     * 
     * @param userAgent the user agent string
     * @param ipAddress the IP address
     * @return formatted device information
     */
    private String generateDeviceInfo(String userAgent, String ipAddress) {
        String browser = extractBrowserInfo(userAgent);
        String os = extractOSInfo(userAgent);
        String maskedIp = maskIpAddress(ipAddress);
        
        return String.format("%s on %s (IP: %s)", 
                           capitalizeFirst(browser), 
                           capitalizeFirst(os), 
                           maskedIp);
    }

    /**
     * Capitalizes the first letter of a string.
     * 
     * @param str the string to capitalize
     * @return capitalized string
     */
    private String capitalizeFirst(String str) {
        if (!StringUtils.hasText(str)) {
            return str;
        }
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }

    /**
     * Sends new device notification email asynchronously.
     * 
     * @param userId the user ID
     * @param userAgent the user agent string
     * @param ipAddress the IP address
     * @param loginTime the login time
     */
    @Async
    public CompletableFuture<Void> sendNewDeviceNotificationAsync(Long userId, String userAgent, 
                                                                 String ipAddress, LocalDateTime loginTime) {
        try {
            // Get user email
            User user = userRepository.findById(userId).orElse(null);
            if (user == null) {
                logger.warn("Cannot send device notification: user not found with ID: {}", userId);
                deviceNotificationFailures.increment();
                return CompletableFuture.completedFuture(null);
            }
            
            // Generate device info for email
            String deviceInfo = generateDeviceInfo(userAgent, ipAddress);
            String formattedLoginTime = loginTime.format(DATE_TIME_FORMATTER);
            
            // Send notification email
            emailService.sendNewDeviceNotification(user.getEmail(), deviceInfo, formattedLoginTime);
            
            deviceNotificationsSent.increment();
            logger.info("New device notification sent to user: {} for device: {}", user.getEmail(), deviceInfo);
            
            return CompletableFuture.completedFuture(null);
            
        } catch (Exception e) {
            deviceNotificationFailures.increment();
            logger.error("Failed to send new device notification for user ID: {}", userId, e);
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Removes all known devices for a user (for security purposes).
     * 
     * @param userId the user ID
     * @return number of devices that were removed
     */
    public int clearUserDevices(Long userId) {
        Set<String> userDevices = knownDevices.remove(userId);
        int removedCount = userDevices != null ? userDevices.size() : 0;
        
        if (removedCount > 0) {
            logger.info("Cleared {} known devices for user ID: {}", removedCount, userId);
        }
        
        return removedCount;
    }

    /**
     * Gets the number of known devices for a user.
     * 
     * @param userId the user ID
     * @return number of known devices
     */
    public int getKnownDeviceCount(Long userId) {
        Set<String> userDevices = knownDevices.get(userId);
        return userDevices != null ? userDevices.size() : 0;
    }

    /**
     * Result class for device detection operations.
     */
    public static class DeviceDetectionResult {
        private final boolean isNewDevice;
        private final boolean isError;
        private final String deviceFingerprint;
        private final String deviceInfo;
        private final String errorMessage;

        private DeviceDetectionResult(boolean isNewDevice, boolean isError, String deviceFingerprint, 
                                    String deviceInfo, String errorMessage) {
            this.isNewDevice = isNewDevice;
            this.isError = isError;
            this.deviceFingerprint = deviceFingerprint;
            this.deviceInfo = deviceInfo;
            this.errorMessage = errorMessage;
        }

        public static DeviceDetectionResult newDevice(String deviceFingerprint, String deviceInfo) {
            return new DeviceDetectionResult(true, false, deviceFingerprint, deviceInfo, null);
        }

        public static DeviceDetectionResult knownDevice(String deviceFingerprint) {
            return new DeviceDetectionResult(false, false, deviceFingerprint, null, null);
        }

        public static DeviceDetectionResult error(String errorMessage) {
            return new DeviceDetectionResult(false, true, null, null, errorMessage);
        }

        public boolean isNewDevice() { return isNewDevice; }
        public boolean isError() { return isError; }
        public String getDeviceFingerprint() { return deviceFingerprint; }
        public String getDeviceInfo() { return deviceInfo; }
        public String getErrorMessage() { return errorMessage; }

        @Override
        public String toString() {
            return String.format("DeviceDetectionResult{isNewDevice=%s, isError=%s, deviceFingerprint='%s', deviceInfo='%s', errorMessage='%s'}", 
                               isNewDevice, isError, deviceFingerprint, deviceInfo, errorMessage);
        }
    }
}