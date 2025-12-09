package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Public;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.dto.LoginRequest;
import ao.sudojed.lss.demo.dto.RegisterRequest;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import ao.sudojed.lss.facade.Auth;
import ao.sudojed.lss.jwt.JwtService;
import ao.sudojed.lss.jwt.TokenPair;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Authentication controller - all endpoints are public.
 * 
 * Demonstrates the use of @Public for endpoints that don't require authentication
 * and the use of Auth facade for authentication operations.
 * 
 * @author Sudojed Team
 */
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;

    public AuthController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    /**
     * Health check - verifies if the API is working.
     * 
     * Usage: GET /auth/health
     */
    @Public
    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
            "status", "UP",
            "service", "LSS Demo API",
            "version", "1.0.0",
            "message", "LazySpringSecurity is running!"
        );
    }

    /**
     * Registers a new user.
     * 
     * Usage: POST /auth/register
     * Body: { "username": "john", "email": "john@example.com", "password": "123456" }
     */
    @Public
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        // Checks if user already exists
        if (userService.findByUsername(request.username()).isPresent()) {
            return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(Map.of(
                    "error", "USER_EXISTS",
                    "message", "User already exists: " + request.username()
                ));
        }

        // Creates the user (password is hashed internally with Auth.hashPassword)
        User user = userService.createUser(
            request.username(),
            request.email(),
            request.password()
        );

        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(Map.of(
                "message", "User created successfully!",
                "userId", user.getId(),
                "username", user.getUsername()
            ));
    }

    /**
     * Login - authenticates and returns JWT tokens.
     * 
     * Usage: POST /auth/login
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
    @Public
    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest request) {
        // Searches for user
        User user = userService.findByUsername(request.username()).orElse(null);

        // Validates credentials using Auth.checkPassword
        if (user == null || !Auth.checkPassword(request.password(), user.getPasswordHash())) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                    "error", "INVALID_CREDENTIALS",
                    "message", "Invalid username or password"
                ));
        }

        // Creates LazyUser to generate tokens
        LazyUser lazyUser = LazyUser.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles(user.getRoles().toArray(new String[0]))
            .claim("email", user.getEmail())
            .claim("displayName", user.getDisplayName())
            .build();

        // Generates tokens
        TokenPair tokens = jwtService.createTokens(lazyUser);

        System.out.println("Login successful: " + user.getUsername());

        return ResponseEntity.ok(tokens.toMap());
    }

    /**
     * Refresh token - generates new access token using refresh token.
     * 
     * Usage: POST /auth/refresh
     * Body: { "refresh_token": "eyJ..." }
     */
    @Public
    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refresh_token");
        
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(Map.of(
                    "error", "MISSING_TOKEN",
                    "message", "refresh_token is required"
                ));
        }

        try {
            TokenPair newTokens = jwtService.refresh(refreshToken);
            return ResponseEntity.ok(newTokens.toMap());
        } catch (Exception e) {
            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                    "error", "INVALID_REFRESH_TOKEN",
                    "message", "Invalid or expired refresh token"
                ));
        }
    }
}
