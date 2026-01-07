package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires basic authentication (any authenticated user).
 *
 * @deprecated Use {@link Secured} instead. This annotation will be removed in a future version.
 *
 * <h2>Migration Guide</h2>
 * <pre>{@code
 * // Before (deprecated)
 * @Authenticated
 * @GetMapping("/profile")
 * public User getProfile() { }
 *
 * // After (recommended)
 * @Secured
 * @GetMapping("/profile")
 * public User getProfile() { }
 * }</pre>
 *
 * @author Sudojed Team
 * @see Secured
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Deprecated(since = "1.1.0", forRemoval = true)
@Secured
public @interface Authenticated {}
