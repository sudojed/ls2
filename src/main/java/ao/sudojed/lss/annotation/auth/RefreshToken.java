package ao.sudojed.lss.annotation.auth;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import ao.sudojed.lss.annotation.Public;

/**
 * Generates an automatic token refresh endpoint.
 * 
 * Apply this annotation to a method in a RestController to automatically
 * handle token refresh. The method body will be ignored and replaced
 * with auto-generated refresh logic.
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * @RestController
 * @RequestMapping("/auth")
 * public class AuthController {
 *     
 *     @RefreshToken
 *     @PostMapping("/refresh")
 *     public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {
 *         return null; // Method body is ignored
 *     }
 * }
 * }</pre>
 * 
 * @author Sudojed Team
 * @since 1.0.0
 * @see Login
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Public // Refresh endpoints are always public
public @interface RefreshToken {
    
    /**
     * The field name in the request body that contains the refresh token.
     * 
     * <p>Default: "refresh_token"</p>
     */
    String tokenField() default "refresh_token";
    
    /**
     * Custom error message for invalid/expired refresh token.
     * 
     * <p>Default: "Invalid or expired refresh token"</p>
     */
    String invalidTokenMessage() default "Invalid or expired refresh token";
    
    /**
     * Custom error message when token is missing.
     * 
     * <p>Default: "refresh_token is required"</p>
     */
    String missingTokenMessage() default "refresh_token is required";
}
