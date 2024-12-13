package com.example.spring_jwt_auth_example.service;

import com.example.spring_jwt_auth_example.entity.RefreshToken;
import com.example.spring_jwt_auth_example.exception.RefreshTokenException;
import com.example.spring_jwt_auth_example.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    @Value("${app.jwt.refreshTokenExpiration}")
    private Duration refreshTokenExpiration;

    private final RefreshTokenRepository refreshTokenRepository;

    public Optional<RefreshToken> findByRefreshToken(String token) {
        log.info("Try to find refresh token by token: {}", token);
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken createRefreshToken(Long userId) {
        log.info("Try to create refresh token for user: {}", userId);
        var refreshToken = RefreshToken.builder()
                .userId(userId)
                .expiryDate(Instant.now().plusMillis(refreshTokenExpiration.toMillis()))
                .token(UUID.randomUUID().toString())
                .build();

        refreshToken = refreshTokenRepository.save(refreshToken);
        log.info("Refresh token created: {}", refreshToken);

        return refreshToken;
    }

    public RefreshToken checkRefreshToken(RefreshToken token) {
        log.info("Try to check refresh token: {}", token);
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            log.info("Refresh token was expired. Try to delete it.");
            refreshTokenRepository.delete(token);
            throw new RefreshTokenException(token.getToken(), "Refresh token was expired. Repeat sign in action!");
        }

        return token;
    }

    public void deleteByUserId(Long userId) {
        log.info("Try to delete refresh tokens for user: {}", userId);
        refreshTokenRepository.deleteByUserId(userId);
    }
}