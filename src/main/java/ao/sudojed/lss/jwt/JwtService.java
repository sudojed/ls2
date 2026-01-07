package ao.sudojed.lss.jwt;

import java.util.Map;

import ao.sudojed.lss.core.LazySecurityProperties;
import ao.sudojed.lss.core.LazyUser;

/**
 * High-level service for JWT operations.
 * Abstracts the complexity of JwtProvider.
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * @Autowired
 * private JwtService jwtService;
 * 
 * public TokenPair login(String username, String password) {
 *     // Validate credentials...
 *     LazyUser user = LazyUser.builder()
 *         .id("123")
 *         .username(username)
 *         .roles("USER")
 *         .build();
 *     
 *     return jwtService.createTokens(user);
 * }
 * 
 * public TokenPair refreshTokens(String refreshToken) {
 *     return jwtService.refresh(refreshToken);
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
public class JwtService {

    private final JwtProvider jwtProvider;
    private final LazySecurityProperties.Jwt jwtConfig;

    public JwtService(JwtProvider jwtProvider, LazySecurityProperties properties) {
        this.jwtProvider = jwtProvider;
        this.jwtConfig = properties.getJwt();
    }

    /**
     * Creates a token pair (access + refresh) for the user.
     */
    public TokenPair createTokens(LazyUser user) {
        String accessToken = jwtProvider.generateToken(user);
        String refreshToken = jwtProvider.generateRefreshToken(user);
        return TokenPair.of(accessToken, refreshToken, jwtConfig.getExpiration() / 1000);
    }

    /**
     * Creates a token pair with additional claims.
     */
    public TokenPair createTokens(LazyUser user, Map<String, Object> extraClaims) {
        String accessToken = jwtProvider.generateToken(user, extraClaims);
        String refreshToken = jwtProvider.generateRefreshToken(user);
        return TokenPair.of(accessToken, refreshToken, jwtConfig.getExpiration() / 1000);
    }

    /**
     * Creates only access token.
     */
    public String createAccessToken(LazyUser user) {
        return jwtProvider.generateToken(user);
    }

    /**
     * Creates only refresh token.
     */
    public String createRefreshToken(LazyUser user) {
        return jwtProvider.generateRefreshToken(user);
    }

    /**
     * Validates token and returns user.
     */
    public LazyUser validate(String token) {
        return jwtProvider.validateToken(token);
    }

    /**
     * Checks if token is valid.
     */
    public boolean isValid(String token) {
        return jwtProvider.isTokenValid(token);
    }

    /**
     * Renews tokens using refresh token.
     * Validates the refresh token and creates a new token pair.
     */
    public TokenPair refresh(String refreshToken) {
        // Use refreshToken method which validates refresh tokens specifically
        String newAccessToken = jwtProvider.refreshToken(refreshToken);
        // Extract user ID from refresh token to generate new refresh token
        String userId = jwtProvider.extractSubject(refreshToken);
        LazyUser user = LazyUser.builder()
                .id(userId)
                .username(userId)
                .build();
        String newRefreshToken = jwtProvider.generateRefreshToken(user);
        return TokenPair.of(newAccessToken, newRefreshToken, jwtConfig.getExpiration() / 1000);
    }

    /**
     * Extracts user from token without validating expiration.
     * Useful for refreshing expired tokens.
     */
    public String extractUserId(String token) {
        return jwtProvider.extractSubject(token);
    }
}
