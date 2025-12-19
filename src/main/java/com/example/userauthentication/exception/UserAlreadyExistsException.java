package com.example.userauthentication.exception;

/**
 * Exception thrown when attempting to register a user with an email that already exists.
 * 
 * Requirements: 1.2
 */
public class UserAlreadyExistsException extends RuntimeException {

    public UserAlreadyExistsException(String message) {
        super(message);
    }

    public UserAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }
}