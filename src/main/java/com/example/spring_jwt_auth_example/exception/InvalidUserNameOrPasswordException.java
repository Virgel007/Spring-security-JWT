package com.example.spring_jwt_auth_example.exception;

public class InvalidUserNameOrPasswordException extends RuntimeException {
    public InvalidUserNameOrPasswordException(String message) {
        super(message);
    }
}
