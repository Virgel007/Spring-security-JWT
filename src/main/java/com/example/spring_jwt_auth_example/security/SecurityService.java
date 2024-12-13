package com.example.spring_jwt_auth_example.security;

import com.example.spring_jwt_auth_example.entity.RefreshToken;
import com.example.spring_jwt_auth_example.entity.User;
import com.example.spring_jwt_auth_example.exception.InvalidUserNameOrPasswordException;
import com.example.spring_jwt_auth_example.exception.RefreshTokenException;
import com.example.spring_jwt_auth_example.repository.UserRepository;
import com.example.spring_jwt_auth_example.security.jwt.JwtUtils;
import com.example.spring_jwt_auth_example.service.RefreshTokenService;
import com.example.spring_jwt_auth_example.web.model.*;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
public class SecurityService {

    private static final Logger log = LoggerFactory.getLogger(SecurityService.class);

    private final AuthenticationManager authenticationManager;

    private final JwtUtils jwtUtils;

    private final RefreshTokenService refreshTokenService;

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    /**
     * This field can be stored in the database to track the number of failed login attempts for each user.
     */
    private final ConcurrentHashMap<String, Integer> userFailureCount = new ConcurrentHashMap<>();

    private final int MAX_FAILURE_COUNT = 5;

    public AuthResponse authenticateUser(LoginRequest loginRequest) {
        log.info("authenticateUser: {}", loginRequest.getUsername());
        boolean isValid = isUserValid(loginRequest);
        if (!isValid) {
            log.info("authenticateUser: invalid username or password");
            throw new InvalidUserNameOrPasswordException("Invalid username or password");
        }

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginRequest.getUsername(),
                loginRequest.getPassword()
        ));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        AppUserDetails userDetails = (AppUserDetails) authentication.getPrincipal();

        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

        log.info("authenticateUser: success");
        return AuthResponse.builder()
                .id(userDetails.getId())
                .token(jwtUtils.generateJwtToken(userDetails))
                .refreshToken(refreshToken.getToken())
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(roles)
                .build();
    }

    public void register(CreateUserRequest createUserRequest) {
        log.info("register: {}", createUserRequest.getUsername());
        var user = User.builder()
                .username(createUserRequest.getUsername())
                .email(createUserRequest.getEmail())
                .isAccountNonLocked(true)
                .password(passwordEncoder.encode(createUserRequest.getPassword()))
                .build();
        user.setRoles(createUserRequest.getRoles());

        userRepository.save(user);
    }

    public RefreshTokenResponse refreshToken(RefreshTokenRequest request) {
        log.info("refreshToken: {}", request.getRefreshToken());
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByRefreshToken(requestRefreshToken)
                .map(refreshTokenService::checkRefreshToken)
                .map(RefreshToken::getUserId)
                .map(userId -> {
                    User tokenOwner = userRepository.findById(userId).orElseThrow(() ->
                            new RefreshTokenException("Exception trying to get token for userId: " + userId));
                    String token = jwtUtils.generateTokenFromUsername(tokenOwner.getUsername());

                    return new RefreshTokenResponse(token, refreshTokenService.createRefreshToken(userId).getToken());
                }).orElseThrow(() -> new RefreshTokenException(requestRefreshToken, "Refresh token not found"));
    }

    public void logout() {
        log.info("logout");
        var currentPrincipal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if (currentPrincipal instanceof AppUserDetails userDetails) {
            Long userId = userDetails.getId();

            refreshTokenService.deleteByUserId(userId);
        }
    }

    public void isBlocked(String username) {
        log.info("isBlocked: {}", username);
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setIsAccountNonLocked(false);
            userRepository.save(user);
        });
    }

    public void isUnBlocked(String username) {
        log.info("isUnBlocked: {}", username);
        userRepository.findByUsername(username).ifPresent(user -> {
            user.setIsAccountNonLocked(true);
            userRepository.save(user);
        });
    }

    public boolean isUserValid(LoginRequest loginRequest) {
        log.info("isUserValid: {}", loginRequest.getUsername());
        boolean isValid = userRepository.findByUsername(loginRequest.getUsername())
                .filter(user -> passwordEncoder.matches(loginRequest.getPassword(), user.getPassword()))
                .isPresent();
        if (!isValid) {
            updateFailureCount(loginRequest.getUsername());
            if (userFailureCount.get(loginRequest.getUsername()) >= MAX_FAILURE_COUNT) {
                isBlocked(loginRequest.getUsername());
                clearFailureCount(loginRequest.getUsername());
            }
        }
        return isValid;
    }

    public void updateFailureCount(String username) {
        log.info("updateFailureCount: {}", username);
        Integer failureCount = userFailureCount.get(username);
        if (failureCount == null) {
            failureCount = 1;
        } else {
            failureCount += 1;
        }
        userFailureCount.put(username, failureCount);
    }

    public void clearFailureCount(String username) {
        log.info("clearFailureCount: {}", username);
        userFailureCount.remove(username);
    }
}