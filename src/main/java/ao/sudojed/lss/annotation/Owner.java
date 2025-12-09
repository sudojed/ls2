package ao.sudojed.lss.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Validates that the current user is the owner of the resource.
 * Useful for endpoints where users can only access their own data.
 * 
 * <h2>Basic Usage</h2>
 * <pre>{@code
 * @Owner(field = "userId")
 * @GetMapping("/users/{userId}/orders")
 * public List<Order> getUserOrders(@PathVariable Long userId) { }
 * }</pre>
 * 
 * <h2>With Admin Bypass</h2>
 * <pre>{@code
 * @Owner(field = "id", adminBypass = true)
 * @PutMapping("/users/{id}")
 * public User updateUser(@PathVariable Long id, @RequestBody User user) {
 *     // User can only edit their own profile
 *     // Admin can edit any profile
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Owner {

    /**
     * Name of the parameter/field that contains the owner ID.
     * Can be path variable, request param, or body field.
     */
    String field();

    /**
     * Field of the principal that contains the user ID.
     * Default: "id"
     */
    String principalField() default "id";

    /**
     * Roles that can bypass the ownership verification.
     */
    String[] bypassRoles() default {"ADMIN"};

    /**
     * Allows ADMIN to bypass the verification.
     */
    boolean adminBypass() default true;

    /**
     * Error message when not the owner.
     */
    String message() default "You can only access your own resources";
}
