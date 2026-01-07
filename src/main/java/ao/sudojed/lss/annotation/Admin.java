package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires ADMIN role to access the resource.
 *
 * @deprecated Use {@link Secured @Secured("ADMIN")} instead. This annotation will be removed in a future version.
 *
 * <h2>Migration Guide</h2>
 * <pre>{@code
 * // Before (deprecated)
 * @Admin
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 *
 * @Admin
 * @RestController
 * @RequestMapping("/api/admin")
 * public class AdminController { }
 *
 * // After (recommended)
 * @Secured("ADMIN")
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 *
 * @Secured("ADMIN")
 * @RestController
 * @RequestMapping("/api/admin")
 * public class AdminController { }
 * }</pre>
 *
 * @author Sudojed Team
 * @see Secured
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Deprecated(since = "1.1.0", forRemoval = true)
@Secured("ADMIN")
public @interface Admin {}
