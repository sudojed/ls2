package ao.sudojed.lss.annotation.auth;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks an entity class as authenticatable.
 * 
 * Use this annotation on your User entity to define which fields
 * contain the authentication data (username/email and password).
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * @Authenticatable(
 *     usernameField = "email",
 *     passwordField = "passwordHash",
 *     rolesField = "roles"
 * )
 * public class User {
 *     private String email;
 *     private String passwordHash;
 *     private Set<String> roles;
 *     // getters...
 * }
 * }</pre>
 * 
 * @author Sudojed Team
 * @since 1.0.0
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Authenticatable {
    
    /**
     * The field name that contains the username/email for authentication.
     * Default: "username"
     */
    String usernameField() default "username";
    
    /**
     * The field name that contains the hashed password.
     * Default: "passwordHash"
     */
    String passwordField() default "passwordHash";
    
    /**
     * The field name that contains the user roles.
     * Default: "roles"
     */
    String rolesField() default "roles";
    
    /**
     * The field name that contains the user ID.
     * Default: "id"
     */
    String idField() default "id";
    
    /**
     * Additional fields to include as JWT claims.
     * Example: {"email", "displayName"}
     */
    String[] claimFields() default {};
}
