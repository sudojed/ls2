package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * JWT configuration for LazySpringSecurity.
 * 
 * <h2>Example</h2>
 * <pre>{@code
 * @JwtConfig(
 *     secret = "${JWT_SECRET}",
 *     expiration = 3600000,  // 1 hour
 *     refreshExpiration = 604800000  // 7 days
 * )
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface JwtConfig {

    /**
     * Secret key for signing JWT tokens.
     * Supports Spring placeholders: ${JWT_SECRET}
     * 
     * IMPORTANT: Use at least 256 bits (32 characters) for HS256.
     */
    String secret() default "";

    /**
     * Access token expiration time in milliseconds.
     * Default: 1 hour (3600000ms)
     */
    long expiration() default 3600000L;

    /**
     * Refresh token expiration time in milliseconds.
     * Default: 7 days (604800000ms)
     */
    long refreshExpiration() default 604800000L;

    /**
     * HTTP header name for the token.
     * Default: "Authorization"
     */
    String header() default "Authorization";

    /**
     * Token prefix in the header.
     * Default: "Bearer "
     */
    String prefix() default "Bearer ";

    /**
     * JWT token issuer.
     */
    String issuer() default "lazy-spring-security";

    /**
     * JWT token audience.
     */
    String audience() default "";

    /**
     * Signing algorithm.
     * Default: HS256
     */
    String algorithm() default "HS256";
}
