package com.example.userauthentication.exception;

/**
 * Exception thrown when a password does not meet security requirements.
 * 
 * Requirements: 1.4
 */
public class InvalidPasswordException extends RuntimeException {

    public InvalidPasswordException(String message) {
        super(message);
    }

    public InvalidPasswordException(String message, Throwable cause) {
        super(message, cause);
    }
}