package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Protects an endpoint/method requiring authentication and specific roles.
 * 
 * <h2>Simple Authentication (any authenticated user)</h2>
 * <pre>{@code
 * @LazySecured
 * @GetMapping("/profile")
 * public User getProfile() { }
 * }</pre>
 * 
 * <h2>Specific Roles</h2>
 * <pre>{@code
 * @LazySecured(roles = "ADMIN")
 * @DeleteMapping("/users/{id}")
 * public void deleteUser(@PathVariable Long id) { }
 * 
 * @LazySecured(roles = {"ADMIN", "MANAGER"})
 * @GetMapping("/reports")
 * public List<Report> getReports() { }
 * }</pre>
 * 
 * <h2>Role Logic</h2>
 * <pre>{@code
 * // Any of the roles (OR)
 * @LazySecured(roles = {"ADMIN", "MANAGER"}, logic = RoleLogic.ANY)
 * 
 * // All roles required (AND)
 * @LazySecured(roles = {"VERIFIED", "PREMIUM"}, logic = RoleLogic.ALL)
 * }</pre>
 * 
 * <h2>Combined with Permissions</h2>
 * <pre>{@code
 * @LazySecured(
 *     roles = "USER",
 *     permissions = "users:read"
 * )
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface LazySecured {

    /**
     * Roles allowed to access the resource.
     * If empty, only authentication is required.
     */
    String[] roles() default {};

    /**
     * Specific permissions required (fine-grained).
     * Example: "users:read", "posts:write"
     */
    String[] permissions() default {};

    /**
     * Logic for multiple roles.
     */
    RoleLogic logic() default RoleLogic.ANY;

    /**
     * Custom error message when access is denied.
     */
    String message() default "Access denied";

    /**
     * SpEL expression for dynamic validation.
     * Example: "#userId == authentication.principal.id"
     */
    String condition() default "";
    
    /**
     * Role evaluation logic.
     */
    enum RoleLogic {
        /** Any of the roles is sufficient (OR) */
        ANY,
        /** All roles are required (AND) */
        ALL
    }
}
