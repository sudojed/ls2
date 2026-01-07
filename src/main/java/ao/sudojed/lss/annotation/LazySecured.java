package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Protects an endpoint/method requiring authentication and specific roles.
 *
 * @deprecated Use {@link Secured} instead. This annotation will be removed in a future version.
 *
 * <h2>Migration Guide</h2>
 * <pre>{@code
 * // Before (deprecated)
 * @LazySecured
 * @LazySecured(roles = "ADMIN")
 * @LazySecured(roles = {"ADMIN", "MANAGER"}, logic = RoleLogic.ANY)
 * @LazySecured(roles = {"VERIFIED", "PREMIUM"}, logic = RoleLogic.ALL)
 *
 * // After (recommended)
 * @Secured
 * @Secured("ADMIN")
 * @Secured({"ADMIN", "MANAGER"})
 * @Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
 * }</pre>
 *
 * @author Sudojed Team
 * @see Secured
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Deprecated(since = "1.1.0", forRemoval = true)
public @interface LazySecured {
    /**
     * Roles allowed to access the resource.
     * If empty, only authentication is required.
     *
     * @deprecated Use {@link Secured#value()} or {@link Secured#roles()} instead.
     */
    @Deprecated
    String[] roles() default {};

    /**
     * Specific permissions required (fine-grained).
     * Example: "users:read", "posts:write"
     *
     * @deprecated Use {@link Secured#permissions()} instead.
     */
    @Deprecated
    String[] permissions() default {};

    /**
     * Logic for multiple roles.
     *
     * @deprecated Use {@link Secured#all()} instead.
     * {@code RoleLogic.ANY} = {@code all = false},
     * {@code RoleLogic.ALL} = {@code all = true}
     */
    @Deprecated
    RoleLogic logic() default RoleLogic.ANY;

    /**
     * Custom error message when access is denied.
     *
     * @deprecated Use {@link Secured#message()} instead.
     */
    @Deprecated
    String message() default "Access denied";

    /**
     * SpEL expression for dynamic validation.
     * Example: "#userId == authentication.principal.id"
     *
     * @deprecated Use {@link Secured#condition()} instead.
     */
    @Deprecated
    String condition() default "";

    /**
     * Role evaluation logic.
     *
     * @deprecated Use {@link Secured#all()} instead.
     */
    @Deprecated
    enum RoleLogic {
        /** Any of the roles is sufficient (OR) - equivalent to {@code @Secured(all = false)} */
        ANY,
        /** All roles are required (AND) - equivalent to {@code @Secured(all = true)} */
        ALL,
    }
}
