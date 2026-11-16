package com.rikkei.microservice.identityservice.service;

import com.rikkei.microservice.identityservice.dto.TokenResponseDTO;
import com.rikkei.microservice.identityservice.entity.RefreshToken;
import com.rikkei.microservice.identityservice.entity.User;
import com.rikkei.microservice.identityservice.exception.TokenRefreshException;
import com.rikkei.microservice.identityservice.repository.RefreshTokenRepository;
import com.rikkei.microservice.identityservice.repository.UserRepository;
import com.rikkei.microservice.identityservice.security.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    @Transactional
    public RefreshToken createRefreshToken(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found with id: " + userId));

        // Xóa token cũ nếu có để đảm bảo tính duy nhất
        refreshTokenRepository.deleteByUser(user);
        refreshTokenRepository.flush();

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }
        return token;
    }

    @Transactional
    public TokenResponseDTO refreshToken(String requestToken) {
        // 1. Tìm RefreshToken trong DB bằng chuỗi requestToken
        RefreshToken refreshToken = refreshTokenRepository.findByToken(requestToken)
                .orElseThrow(() -> new TokenRefreshException(requestToken, "Refresh token is not in database!"));

        // 2. Nếu token đã hết hạn -> Xóa và ném Exception
        if (refreshToken.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenRefreshException(requestToken, "Refresh token was expired. Please make a new signin request");
        }

        // Lấy User từ token cũ
        User user = refreshToken.getUser();

        // 3. (QUAN TRỌNG - Rotation): Xóa bản ghi Refresh Token cũ khỏi DB
        refreshTokenRepository.delete(refreshToken);
        refreshTokenRepository.flush();

        // 4. Lấy User từ token cũ, gọi JwtUtils để tạo Access Token mới
        String newAccessToken = jwtUtils.generateAccessToken(user);

        // 5. Tạo Refresh Token hoàn toàn mới
        RefreshToken newRefreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDurationMs))
                .build();
        newRefreshToken = refreshTokenRepository.save(newRefreshToken);

        // 6. Trả về cặp Token mới cho Client
        return TokenResponseDTO.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .tokenType("Bearer")
                .build();
    }
}
