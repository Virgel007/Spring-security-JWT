package com.example.spring_jwt_auth_example.web.controller;

import com.example.spring_jwt_auth_example.exception.AlreadyExitsException;
import com.example.spring_jwt_auth_example.repository.UserRepository;
import com.example.spring_jwt_auth_example.security.SecurityService;
import com.example.spring_jwt_auth_example.web.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final UserRepository userRepository;

    private final SecurityService securityService;

    @PostMapping("/signin")
    public ResponseEntity<AuthResponse> authUser(@RequestBody LoginRequest loginRequest) {
        log.info("Try to sign in with username: {}", loginRequest.getUsername());
        return ResponseEntity.ok(securityService.authenticateUser(loginRequest));
    }

    @PostMapping("/register")
    public ResponseEntity<SimpleResponse> registerUser(@RequestBody CreateUserRequest createUserRequest) {
        if (userRepository.existsByUsername(createUserRequest.getUsername())) {
            throw new AlreadyExitsException("Username already exists!");
        }

        if (userRepository.existsByEmail(createUserRequest.getEmail())) {
            throw new AlreadyExitsException("Email already exists!");
        }

        log.info("Try to register user with username: {}", createUserRequest.getUsername());
        securityService.register(createUserRequest);

        return ResponseEntity.ok(new SimpleResponse("User create!"));
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<RefreshTokenResponse> refreshToken(@RequestBody RefreshTokenRequest request) {
        log.info("Try to refresh token for user with id: {}", request.toString());
        return ResponseEntity.ok(securityService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<SimpleResponse> logoutUser(@AuthenticationPrincipal UserDetails userDetails) {
        log.info("Try to logout user with username: {}", userDetails.getUsername());
        securityService.logout();

        return ResponseEntity.ok(new SimpleResponse("User logout. Username is:" + userDetails.getUsername()));
    }
}