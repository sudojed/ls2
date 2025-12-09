package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import ao.sudojed.lss.config.LazySecurityAutoConfiguration;

/**
 * Enables LazySpringSecurity in a Spring Boot application.
 * 
 * <h2>Basic Usage</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(secret = "${app.jwt.secret}"),
 *     publicPaths = {"/api/public/**", "/health", "/swagger-ui/**"}
 * )
 * @SpringBootApplication
 * public class MyApplication { }
 * }</pre>
 * 
 * <h2>Full Configuration</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(
 *         secret = "${JWT_SECRET}",
 *         expiration = 86400000,
 *         header = "Authorization",
 *         prefix = "Bearer "
 *     ),
 *     publicPaths = {"/api/auth/**", "/actuator/health"},
 *     defaultRole = "USER",
 *     csrfEnabled = false,
 *     corsEnabled = true
 * )
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(LazySecurityAutoConfiguration.class)
public @interface EnableLazySecurity {

    /**
     * JWT configuration. Required for stateless authentication.
     */
    JwtConfig jwt() default @JwtConfig;

    /**
     * Public paths that do not require authentication.
     * Supports Ant patterns: /api/**, /public/*, etc.
     */
    String[] publicPaths() default {};

    /**
     * Default role for authenticated users without a specific role.
     */
    String defaultRole() default "USER";

    /**
     * Enables/disables CSRF protection.
     * Default: false (REST APIs typically don't need it)
     */
    boolean csrfEnabled() default false;

    /**
     * Enables/disables CORS.
     */
    boolean corsEnabled() default true;

    /**
     * Allowed origins for CORS.
     */
    String[] corsOrigins() default {"*"};

    /**
     * Allowed HTTP methods for CORS.
     */
    String[] corsMethods() default {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"};

    /**
     * Allowed headers for CORS.
     */
    String[] corsHeaders() default {"*"};

    /**
     * Paths that require HTTPS.
     */
    String[] securePaths() default {};

    /**
     * Enables debug logging for troubleshooting.
     */
    boolean debug() default false;
}
