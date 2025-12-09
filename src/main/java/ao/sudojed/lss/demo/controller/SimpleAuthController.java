package ao.sudojed.lss.demo.controller;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ao.sudojed.lss.annotation.auth.Login;
import ao.sudojed.lss.annotation.auth.RefreshToken;
import ao.sudojed.lss.annotation.auth.Register;
import ao.sudojed.lss.demo.dto.LoginRequest;
import ao.sudojed.lss.demo.dto.RegisterRequest;
import ao.sudojed.lss.demo.service.UserService;

/**
 * Simplified Authentication Controller using auto-generated endpoints.
 * 
 * This controller demonstrates how to create a complete authentication API
 * with ZERO boilerplate code using LSS annotations.
 * 
 * <h2>Features</h2>
 * <ul>
 *   <li>@Login - Auto-generates login logic</li>
 *   <li>@Register - Auto-generates registration logic</li>
 *   <li>@RefreshToken - Auto-generates token refresh logic</li>
 * </ul>
 * 
 * <h2>Comparison</h2>
 * 
 * <h3>Traditional approach (50+ lines):</h3>
 * <pre>{@code
 * @PostMapping("/login")
 * public ResponseEntity<?> login(@RequestBody LoginRequest request) {
 *     User user = userService.findByUsername(request.username()).orElse(null);
 *     if (user == null || !Auth.checkPassword(request.password(), user.getPasswordHash())) {
 *         return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
 *     }
 *     LazyUser lazyUser = LazyUser.builder()
 *         .id(user.getId())
 *         .username(user.getUsername())
 *         .roles(user.getRoles().toArray(new String[0]))
 *         .claim("email", user.getEmail())
 *         .build();
 *     TokenPair tokens = jwtService.createTokens(lazyUser);
 *     return ResponseEntity.ok(tokens.toMap());
 * }
 * }</pre>
 * 
 * <h3>With @Login (3 lines!):</h3>
 * <pre>{@code
 * @Login(userService = UserService.class, claims = {"email", "displayName"})
 * @PostMapping("/login")
 * public ResponseEntity<?> login(@RequestBody LoginRequest request) { return null; }
 * }</pre>
 * 
 * @author Sudojed Team
 * @since 1.0.0
 */
@RestController
@RequestMapping("/api/v2/auth")
public class SimpleAuthController {

    /**
     * Login endpoint - automatically handles authentication.
     * 
     * POST /api/v2/auth/login
     * Body: { "username": "john", "password": "123456" }
     * 
     * Returns:
     * {
     *   "access_token": "eyJ...",
     *   "refresh_token": "eyJ...",
     *   "token_type": "Bearer",
     *   "expires_in": 3600
     * }
     */
    @Login(
        userService = UserService.class,
        findMethod = "findByUsername",
        claims = {"email", "displayName"},
        includeUserInfo = true
    )
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        // Method body is completely ignored!
        // The @Login annotation handles everything automatically.
        return null;
    }

    /**
     * Registration endpoint - automatically handles user creation.
     * 
     * POST /api/v2/auth/register
     * Body: { "username": "newuser", "email": "new@example.com", "password": "123456" }
     * 
     * Returns:
     * {
     *   "message": "User created successfully!",
     *   "id": "user-abc123",
     *   "username": "newuser"
     * }
     */
    @Register(
        userService = UserService.class,
        createMethod = "createUser",
        existsMethod = "findByUsername",
        requestFields = {"username", "email", "password"},
        uniqueField = "username",
        responseFields = {"id", "username"},
        autoLogin = false
    )
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        // Method body is completely ignored!
        return null;
    }

    /**
     * Registration with auto-login - creates user and returns tokens.
     * 
     * POST /api/v2/auth/register-login
     * Body: { "username": "newuser", "email": "new@example.com", "password": "123456" }
     * 
     * Returns tokens directly after registration.
     */
    @Register(
        userService = UserService.class,
        createMethod = "createUser",
        autoLogin = true  // Returns JWT tokens after registration
    )
    @PostMapping("/register-login")
    public ResponseEntity<?> registerAndLogin(@RequestBody RegisterRequest request) {
        return null;
    }

    /**
     * Token refresh endpoint - automatically handles token refresh.
     * 
     * POST /api/v2/auth/refresh
     * Body: { "refresh_token": "eyJ..." }
     * 
     * Returns new tokens.
     */
    @RefreshToken
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        // Method body is completely ignored!
        return null;
    }
}
