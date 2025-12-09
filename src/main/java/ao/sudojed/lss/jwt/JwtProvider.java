package ao.sudojed.lss.jwt;

import java.util.Map;

import ao.sudojed.lss.core.LazyUser;

/**
 * Interface for JWT token generation and validation.
 * Implement this interface to customize token logic.
 * 
 * <h2>Default Implementation</h2>
 * LSS provides {@link DefaultJwtProvider} that works out-of-the-box.
 * 
 * <h2>Custom Implementation</h2>
 * <pre>{@code
 * @Component
 * public class MyJwtProvider implements JwtProvider {
 *     @Override
 *     public String generateToken(LazyUser user) {
 *         // Your custom logic
 *     }
 *     // ...
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
public interface JwtProvider {

    /**
     * Generates an access token for the user.
     */
    String generateToken(LazyUser user);

    /**
     * Generates an access token with additional claims.
     */
    String generateToken(LazyUser user, Map<String, Object> extraClaims);

    /**
     * Generates a refresh token for the user.
     */
    String generateRefreshToken(LazyUser user);

    /**
     * Validates a token and returns the user.
     * 
     * @throws ao.sudojed.lss.exception.LazySecurityException if token is invalid
     */
    LazyUser validateToken(String token);

    /**
     * Checks if a token is valid (not expired, correct signature).
     */
    boolean isTokenValid(String token);

    /**
     * Checks if a token is expired.
     */
    boolean isTokenExpired(String token);

    /**
     * Extracts the subject (usually userId or username) from the token.
     */
    String extractSubject(String token);

    /**
     * Extracts a specific claim from the token.
     */
    <T> T extractClaim(String token, String claimName, Class<T> type);

    /**
     * Extracts all claims from the token.
     */
    Map<String, Object> extractAllClaims(String token);

    /**
     * Renews a token (generates new access token from refresh token).
     */
    String refreshToken(String refreshToken);
}
