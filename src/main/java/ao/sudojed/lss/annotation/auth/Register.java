package ao.sudojed.lss.annotation.auth;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import ao.sudojed.lss.annotation.Public;

/**
 * Generates an automatic user registration endpoint.
 * 
 * Apply this annotation to a method in a RestController to automatically
 * handle user registration. The method body will be ignored and replaced
 * with auto-generated registration logic.
 * 
 * <h2>Basic Usage</h2>
 * <pre>{@code
 * @RestController
 * @RequestMapping("/auth")
 * public class AuthController {
 *     
 *     @Register(
 *         userService = UserService.class,
 *         createMethod = "createUser"
 *     )
 *     @PostMapping("/register")
 *     public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
 *         return null; // Method body is ignored
 *     }
 * }
 * }</pre>
 * 
 * <h2>Advanced Usage</h2>
 * <pre>{@code
 * @Register(
 *     userService = UserService.class,
 *     createMethod = "createUser",
 *     existsMethod = "findByUsername",
 *     requestFields = {"username", "email", "password"},
 *     autoLogin = true
 * )
 * @PostMapping("/register")
 * public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
 *     return null;
 * }
 * }</pre>
 * 
 * @author Sudojed Team
 * @since 1.0.0
 * @see Login
 * @see Authenticatable
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Public // Register endpoints are always public
public @interface Register {
    
    /**
     * The service class that provides user creation functionality.
     */
    Class<?> userService();
    
    /**
     * The method name in the service to create users.
     * Must accept the registration fields as parameters.
     * 
     * <p>Default: "createUser"</p>
     */
    String createMethod() default "createUser";
    
    /**
     * The method name to check if user already exists.
     * Must accept username and return Optional&lt;?&gt;.
     * 
     * <p>Default: "findByUsername"</p>
     */
    String existsMethod() default "findByUsername";
    
    /**
     * The field names expected in the request body.
     * These will be passed to the create method in order.
     * 
     * <p>Default: {"username", "email", "password"}</p>
     */
    String[] requestFields() default {"username", "email", "password"};
    
    /**
     * The field in request to check for existing user.
     * 
     * <p>Default: "username"</p>
     */
    String uniqueField() default "username";
    
    /**
     * Whether to automatically log in after registration.
     * If true, returns JWT tokens instead of just success message.
     * 
     * <p>Default: false</p>
     */
    boolean autoLogin() default false;
    
    /**
     * Custom error message when user already exists.
     * Use {field} as placeholder for the unique field value.
     * 
     * <p>Default: "User already exists"</p>
     */
    String existsMessage() default "User already exists";
    
    /**
     * Fields to include in the success response.
     * 
     * <p>Default: {"id", "username"}</p>
     */
    String[] responseFields() default {"id", "username"};
}
