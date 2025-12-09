/**
 * Authentication annotations for automatic endpoint generation.
 * 
 * <h2>Overview</h2>
 * <p>This package provides annotations that automatically generate complete
 * authentication endpoints without requiring manual implementation.</p>
 * 
 * <h2>Available Annotations</h2>
 * <ul>
 *   <li>{@link ao.sudojed.lss.annotation.auth.Login} - Auto-generates login endpoint</li>
 *   <li>{@link ao.sudojed.lss.annotation.auth.Register} - Auto-generates registration endpoint</li>
 *   <li>{@link ao.sudojed.lss.annotation.auth.RefreshToken} - Auto-generates token refresh endpoint</li>
 *   <li>{@link ao.sudojed.lss.annotation.auth.Authenticatable} - Marks an entity as authenticatable</li>
 * </ul>
 * 
 * <h2>Quick Start</h2>
 * <pre>{@code
 * @RestController
 * @RequestMapping("/auth")
 * public class AuthController {
 *     
 *     // Complete login endpoint in 3 lines!
 *     @Login(userService = UserService.class, claims = {"email"})
 *     @PostMapping("/login")
 *     public ResponseEntity<?> login(@RequestBody LoginRequest request) { return null; }
 *     
 *     // Complete registration in 3 lines!
 *     @Register(userService = UserService.class, autoLogin = true)
 *     @PostMapping("/register")
 *     public ResponseEntity<?> register(@RequestBody RegisterRequest request) { return null; }
 *     
 *     // Token refresh in 2 lines!
 *     @RefreshToken
 *     @PostMapping("/refresh")
 *     public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) { return null; }
 * }
 * }</pre>
 * 
 * <h2>How it Works</h2>
 * <p>These annotations work via AOP (Aspect-Oriented Programming). When a method
 * annotated with @Login, @Register, or @RefreshToken is called, the
 * {@link ao.sudojed.lss.aspect.AuthEndpointAspect} intercepts the call and
 * executes the authentication logic automatically. The original method body
 * is completely ignored.</p>
 * 
 * <h2>Comparison: Traditional vs LSS</h2>
 * 
 * <h3>Traditional Login (50+ lines):</h3>
 * <pre>{@code
 * @PostMapping("/login")
 * public ResponseEntity<?> login(@RequestBody LoginRequest request) {
 *     User user = userService.findByUsername(request.username()).orElse(null);
 *     if (user == null || !passwordEncoder.matches(request.password(), user.getPasswordHash())) {
 *         return ResponseEntity.status(401).body(Map.of(
 *             "error", "INVALID_CREDENTIALS",
 *             "message", "Invalid username or password"
 *         ));
 *     }
 *     LazyUser lazyUser = LazyUser.builder()
 *         .id(user.getId())
 *         .username(user.getUsername())
 *         .roles(user.getRoles().toArray(new String[0]))
 *         .claim("email", user.getEmail())
 *         .claim("displayName", user.getDisplayName())
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
 * @see ao.sudojed.lss.annotation.auth.Login
 * @see ao.sudojed.lss.annotation.auth.Register
 * @see ao.sudojed.lss.annotation.auth.RefreshToken
 * @see ao.sudojed.lss.aspect.AuthEndpointAspect
 */
package ao.sudojed.lss.annotation.auth;
