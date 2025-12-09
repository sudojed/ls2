package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Applies rate limiting to an endpoint.
 * Protects against abuse and DDoS attacks.
 * 
 * <h2>Basic Usage</h2>
 * <pre>{@code
 * @RateLimit(requests = 100, window = 60)  // 100 requests per minute
 * @PostMapping("/api/data")
 * public Data processData() { }
 * }</pre>
 * 
 * <h2>Per User</h2>
 * <pre>{@code
 * @RateLimit(requests = 10, window = 60, perUser = true)
 * @PostMapping("/messages")
 * public Message sendMessage() { }
 * }</pre>
 * 
 * <h2>Login Endpoints</h2>
 * <pre>{@code
 * @RateLimit(requests = 5, window = 300, key = "ip")  // 5 attempts per 5 min per IP
 * @PostMapping("/login")
 * public Token login() { }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RateLimit {

    /**
     * Maximum number of requests allowed in the time window.
     */
    int requests();

    /**
     * Time window in seconds.
     */
    int window();

    /**
     * Key for rate limiting: "ip", "user", "token", or SpEL expression.
     * Default: "ip"
     */
    String key() default "ip";

    /**
     * If true, limit is applied per authenticated user.
     */
    boolean perUser() default false;

    /**
     * Error message when limit is exceeded.
     */
    String message() default "Rate limit exceeded. Please try again later.";

    /**
     * HTTP code when limit is exceeded.
     * Default: 429 Too Many Requests
     */
    int statusCode() default 429;
}
