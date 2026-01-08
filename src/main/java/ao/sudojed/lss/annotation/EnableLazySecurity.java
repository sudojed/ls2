package ao.sudojed.lss.annotation;

import ao.sudojed.lss.config.LazySecurityAutoConfiguration;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.context.annotation.Import;

/**
 * Enables LazySpringSecurity in a Spring Boot application.
 *
 * <h2>Basic Usage (Annotation-Driven)</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(secret = "${app.jwt.secret}")
 * )
 * @SpringBootApplication
 * public class MyApplication { }
 *
 * // Use @Public and @Secured annotations on controllers
 * @RestController
 * public class MyController {
 *     @Public
 *     @GetMapping("/public-endpoint")
 *     public String publicEndpoint() { return "No auth needed"; }
 *
 *     @Secured
 *     @GetMapping("/protected-endpoint")
 *     public String protectedEndpoint() { return "Auth required"; }
 * }
 * }</pre>
 *
 * <h2>Legacy Configuration (Optional)</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(
 *         secret = "${JWT_SECRET}",
 *         expiration = 86400000,
 *         header = "Authorization",
 *         prefix = "Bearer "
 *     ),
 *     publicPaths = {"/legacy/public/**", "/actuator/health"}, // Optional - use @Public instead
 *     defaultRole = "USER",
 *     csrfEnabled = false,
 *     corsEnabled = true
 * )
 * }</pre>
 *
 * <h2>Migration Guide</h2>
 * <p>Instead of manually listing paths in {@code publicPaths}, use annotations:</p>
 * <ul>
 *   <li>{@code @Public} - Makes endpoint public (no authentication required)</li>
 *   <li>{@code @Secured} - Requires authentication (any authenticated user)</li>
 *   <li>{@code @Secured("ROLE")} - Requires specific role</li>
 *   <li>{@code @Register/@Login/@RefreshToken} - Automatically public</li>
 * </ul>
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
     *
     * <p><strong>DEPRECATED:</strong> Use {@code @Public} annotation on controller methods instead.
     * This provides better maintainability and automatic endpoint discovery.</p>
     *
     * <p>Examples:</p>
     * <pre>{@code
     * // OLD WAY (still works but not recommended)
     * @EnableLazySecurity(publicPaths = {"/api/public/**"})
     *
     * // NEW WAY (recommended)
     * @Public
     * @GetMapping("/api/public/endpoint")
     * public String endpoint() { return "public"; }
     * }</pre>
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
    String[] corsOrigins() default { "*" };

    /**
     * Allowed HTTP methods for CORS.
     */
    String[] corsMethods() default {
        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
    };

    /**
     * Allowed headers for CORS.
     */
    String[] corsHeaders() default { "*" };

    /**
     * Paths that require HTTPS.
     */
    String[] securePaths() default {};

    /**
     * Enables debug logging for troubleshooting.
     */
    boolean debug() default false;
}
