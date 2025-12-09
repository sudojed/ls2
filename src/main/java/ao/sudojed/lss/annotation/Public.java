package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an endpoint or method as PUBLIC (no authentication required).
 * 
 * <h2>Usage on Methods</h2>
 * <pre>{@code
 * @Public
 * @PostMapping("/login")
 * public Token login(@RequestBody LoginRequest request) {
 *     return authService.login(request);
 * }
 * 
 * @Public
 * @GetMapping("/health")
 * public Health healthCheck() {
 *     return Health.up();
 * }
 * }</pre>
 * 
 * <h2>Usage on Classes</h2>
 * <pre>{@code
 * @Public
 * @RestController
 * @RequestMapping("/api/public")
 * public class PublicController {
 *     // All endpoints are public
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Public {
    
    /**
     * Optional description for documentation.
     */
    String description() default "";
}
