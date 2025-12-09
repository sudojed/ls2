package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Requires basic authentication (any authenticated user).
 * Convenient shortcut for {@code @LazySecured()}.
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * @Authenticated
 * @GetMapping("/profile")
 * public User getProfile() { }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
@LazySecured
public @interface Authenticated {
}
