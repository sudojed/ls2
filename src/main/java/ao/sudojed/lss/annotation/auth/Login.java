package ao.sudojed.lss.annotation.auth;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import ao.sudojed.lss.annotation.Public;

/**
 * Generates an automatic login endpoint.
 * 
 * Apply this annotation to a method in a RestController to automatically
 * handle user authentication. The method body will be ignored and replaced
 * with auto-generated login logic.
 * 
 * <h2>Basic Usage</h2>
 * <pre>{@code
 * @RestController
 * @RequestMapping("/auth")
 * public class AuthController {
 *     
 *     @Login(
 *         userService = UserService.class,
 *         findMethod = "findByUsername"
 *     )
 *     @PostMapping("/login")
 *     public ResponseEntity<?> login(@RequestBody LoginRequest request) {
 *         return null; // Method body is ignored
 *     }
 * }
 * }</pre>
 * 
 * <h2>Advanced Usage with Entity Mapping</h2>
 * <pre>{@code
 * @Login(
 *     userService = UserService.class,
 *     findMethod = "findByEmail",
 *     usernameField = "email",
 *     passwordField = "passwordHash",
 *     rolesField = "roles",
 *     idField = "id",
 *     claims = {"email", "displayName"}
 * )
 * @PostMapping("/login")
 * public ResponseEntity<?> login(@RequestBody LoginRequest request) {
 *     return null;
 * }
 * }</pre>
 * 
 * <h2>How it Works</h2>
 * <ol>
 *   <li>Intercepts the annotated method via AOP</li>
 *   <li>Extracts username and password from the request body</li>
 *   <li>Calls the specified service method to find the user</li>
 *   <li>Validates the password using Auth.checkPassword()</li>
 *   <li>Generates JWT tokens using JwtService</li>
 *   <li>Returns the tokens or an error response</li>
 * </ol>
 * 
 * @author Sudojed Team
 * @since 1.0.0
 * @see Authenticatable
 * @see ao.sudojed.lss.aspect.LoginAspect
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Public // Login endpoints are always public
public @interface Login {
    
    /**
     * The service class that provides user lookup functionality.
     * Must have a method that accepts a username/email and returns Optional&lt;User&gt;.
     * 
     * <p>Example: UserService.class</p>
     */
    Class<?> userService();
    
    /**
     * The method name in the service to find users.
     * Must accept a String (username/email) and return Optional&lt;?&gt;.
     * 
     * <p>Default: "findByUsername"</p>
     */
    String findMethod() default "findByUsername";
    
    /**
     * The field name in the user entity that contains the username/email.
     * Used to extract the value for JWT claims.
     * 
     * <p>Default: "username"</p>
     */
    String usernameField() default "username";
    
    /**
     * The field name in the user entity that contains the hashed password.
     * 
     * <p>Default: "passwordHash"</p>
     */
    String passwordField() default "passwordHash";
    
    /**
     * The field name in the user entity that contains the user's roles.
     * Can be a Collection, Array, or single String.
     * 
     * <p>Default: "roles"</p>
     */
    String rolesField() default "roles";
    
    /**
     * The field name in the user entity that contains the user's ID.
     * 
     * <p>Default: "id"</p>
     */
    String idField() default "id";
    
    /**
     * Additional fields from the user entity to include as JWT claims.
     * 
     * <p>Example: {"email", "displayName", "department"}</p>
     */
    String[] claims() default {};
    
    /**
     * The field name in the request body that contains the username/email.
     * 
     * <p>Default: "username"</p>
     */
    String requestUsernameField() default "username";
    
    /**
     * The field name in the request body that contains the password.
     * 
     * <p>Default: "password"</p>
     */
    String requestPasswordField() default "password";
    
    /**
     * Custom error message for invalid credentials.
     * 
     * <p>Default: "Invalid username or password"</p>
     */
    String invalidCredentialsMessage() default "Invalid username or password";
    
    /**
     * Whether to include user info in the response (excluding sensitive data).
     * 
     * <p>Default: false</p>
     */
    boolean includeUserInfo() default false;
}
