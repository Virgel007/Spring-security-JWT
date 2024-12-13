package com.example.spring_jwt_auth_example.web.controller;

import com.example.spring_jwt_auth_example.security.SecurityService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
@RequestMapping("/api/v1/app")
public class AppController {

    private final SecurityService securityService;

    @GetMapping("/all")
    public String allAccess() {
        return "public response data";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin response data";
    }

    @GetMapping("/manager")
    @PreAuthorize("hasRole('MANAGER')")
    public String moderatorAccess() {
        return "Manager response data";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MANAGER') or hasRole('ADMIN')")
    public String userAccess() {
        return "User response data";
    }

    @PutMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> unblockUser(@RequestBody String username) {
        log.info("Unblock user: {}", username);
        securityService.isUnBlocked(username);
        return ResponseEntity.ok("User unblocked!");
    }
}
