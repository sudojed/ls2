# LazySpringSecurity (LSS)

> **A lightweight, annotation-driven security framework that abstracts Spring Security complexity into a readable, developer-friendly DSL.**

[![Java](https://img.shields.io/badge/Java-21+-orange.svg)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4+-green.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Features

- **Zero Configuration** - Works out of the box with sensible defaults
- **Annotation-Driven** - Simple, readable annotations for security (`@Public`, `@Authenticated`, `@LazySecured`, `@Admin`, `@Owner`)
- **Static Facades** - `Auth` and `Guard` facades for programmatic security checks anywhere in your code
- **JWT Support** - Built-in JWT authentication with refresh tokens via `JwtService`
- **Role & Permission Based** - Fine-grained access control with AND/OR logic
- **Rate Limiting** - Built-in `@RateLimit` annotation for endpoint protection
- **Password Utilities** - BCrypt hashing via `PasswordUtils`
- **Context Access** - Easy user access via `LazySecurityContext` and `LazyAuth`
- **Spring Boot Native** - Seamless auto-configuration
- **Automatic User Injection** - `LazyUser` automatically injected into controller methods

---

## Installation

### Maven

```xml
<dependency>
    <groupId>ao.sudojed</groupId>
    <artifactId>lazy-spring-security</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

### Gradle

```groovy
implementation 'ao.sudojed:lazy-spring-security:1.0.0-SNAPSHOT'
```

---

## Quick Start

### 1. Enable LazySpringSecurity

```java
@SpringBootApplication
@EnableLazySecurity(
    jwt = @JwtConfig(secret = "${JWT_SECRET}"),
    publicPaths = {"/api/auth/**", "/health"}
)
public class MyApplication {
    public static void main(String[] args) {
        SpringApplication.run(MyApplication.class, args);
    }
}
```

### 2. Use Annotations

```java
@RestController
@RequestMapping("/api")
public class MyController {

    // Public endpoint - no authentication required
    @Public
    @GetMapping("/health")
    public String health() {
        return "OK";
    }

    // Requires authentication - LazyUser auto-injected
    @Authenticated
    @GetMapping("/profile")
    public User getProfile(LazyUser user) {
        return userService.findById(user.getId());
    }

    // Requires ADMIN role
    @Admin
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }

    // Flexible role checking with @LazySecured
    @LazySecured(roles = {"ADMIN", "MODERATOR"}, logic = RoleLogic.ANY)
    @PutMapping("/posts/{id}")
    public Post updatePost(@PathVariable Long id, @RequestBody Post post) {
        return postService.update(id, post);
    }

    // Resource owner only (with admin bypass)
    @Owner(field = "userId", adminBypass = true)
    @GetMapping("/users/{userId}/settings")
    public Settings getSettings(@PathVariable String userId) {
        return settingsService.getByUserId(userId);
    }

    // Rate limiting - 10 requests per 60 seconds
    @RateLimit(requests = 10, window = 60)
    @PostMapping("/send-email")
    public void sendEmail(@RequestBody EmailRequest request) {
        emailService.send(request);
    }
}
```

### 3. Configure JWT (application.yml)

```yaml
lazy-security:
  enabled: true
  jwt:
    secret: ${JWT_SECRET:your-256-bit-secret-key-here}
    expiration: 86400000  # 24 hours in ms
    refresh-expiration: 604800000  # 7 days in ms
  cors:
    enabled: true
    allowed-origins:
      - http://localhost:3000
```

---

## Annotations Reference

### `@EnableLazySecurity`
Enables LazySpringSecurity in your application.

```java
@EnableLazySecurity(
    jwt = @JwtConfig(
        secret = "${JWT_SECRET}",
        expiration = 86400000,
        header = "Authorization",
        prefix = "Bearer "
    ),
    publicPaths = {"/api/auth/**", "/actuator/health"},
    defaultRole = "USER",
    csrfEnabled = false,
    corsEnabled = true,
    corsOrigins = {"http://localhost:3000"},
    debug = false
)
@SpringBootApplication
public class MyApplication { }
```

### `@Public`
Marks an endpoint as publicly accessible (no authentication required).

```java
@Public
@GetMapping("/docs")
public String getDocs() { ... }

// With reason for documentation
@Public(reason = "Health check for load balancer")
@GetMapping("/health")
public String health() { ... }
```

### `@Authenticated`
Requires user to be logged in (any valid authentication).

```java
@Authenticated
@GetMapping("/me")
public User getCurrentUser(LazyUser user) { ... }
```

### `@Admin`
Shortcut annotation that requires ADMIN role.

```java
@Admin
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) { ... }
```

### `@LazySecured`
Flexible access control with roles and permissions.

```java
// Single role
@LazySecured(roles = "MANAGER")
@GetMapping("/reports")
public List<Report> getReports() { ... }

// Multiple roles (OR logic - any role grants access)
@LazySecured(roles = {"ADMIN", "MODERATOR"}, logic = RoleLogic.ANY)
@PutMapping("/posts/{id}")
public Post updatePost(@PathVariable Long id) { ... }

// Multiple roles (AND logic - all roles required)
@LazySecured(roles = {"VERIFIED", "PREMIUM"}, logic = RoleLogic.ALL)
@GetMapping("/exclusive-content")
public Content getExclusiveContent() { ... }

// With permissions
@LazySecured(roles = "USER", permissions = "posts:write")
@PostMapping("/posts")
public Post createPost(@RequestBody Post post) { ... }

// Custom error message
@LazySecured(roles = "ADMIN", message = "Admin access required")
@GetMapping("/admin/stats")
public Stats getStats() { ... }
```

### `@Owner`
Restricts access to the owner of a resource.

```java
// Match userId path variable with current user
@Owner(field = "userId")
@GetMapping("/users/{userId}/orders")
public List<Order> getUserOrders(@PathVariable Long userId) { ... }

// With admin bypass
@Owner(field = "id", adminBypass = true)
@PutMapping("/users/{id}")
public User updateUser(@PathVariable Long id, @RequestBody User user) { ... }

// With custom bypass roles
@Owner(field = "userId", bypassRoles = {"ADMIN", "SUPPORT"})
@DeleteMapping("/users/{userId}")
public void deleteUser(@PathVariable String userId) { ... }
```

### `@RateLimit`
Limits request rate to prevent abuse.

```java
// 100 requests per minute per IP
@RateLimit(requests = 100, window = 60)
@PostMapping("/login")
public AuthResponse login(@RequestBody LoginRequest request) { ... }

// Per user rate limiting
@RateLimit(requests = 10, window = 60, perUser = true)
@PostMapping("/messages")
public Message sendMessage(@RequestBody Message msg) { ... }

// Custom key-based rate limiting
@RateLimit(requests = 5, window = 300, key = "ip", message = "Too many login attempts")
@PostMapping("/auth/login")
public Token login(@RequestBody LoginRequest request) { ... }
```

---

## Static Facades

### `Auth` Facade

The `Auth` facade provides static access to authentication operations from anywhere in your codebase.

```java
// Check authentication status
if (Auth.check()) {
    // User is authenticated
}

if (Auth.guest()) {
    // User is not authenticated
}

// Get current user
LazyUser user = Auth.user();
String userId = Auth.id();
String username = Auth.username();

// Role and permission checks
if (Auth.hasRole("ADMIN")) { ... }
if (Auth.hasAnyRole("ADMIN", "MANAGER")) { ... }
if (Auth.hasAllRoles("VERIFIED", "PREMIUM")) { ... }
if (Auth.can("posts:write")) { ... }
if (Auth.isAdmin()) { ... }

// Conditional execution
Auth.ifAuthenticated(user -> {
    System.out.println("Hello, " + user.getUsername());
});

Auth.ifGuest(() -> {
    System.out.println("Please log in");
});

// Get value or default
String name = Auth.getOrDefault(u -> u.getUsername(), "Guest");

// Access claims from JWT
String department = (String) Auth.claim("department");
Integer level = Auth.claim("level", 1);

// Require authentication (throws UnauthorizedException if not authenticated)
Auth.requireAuth();

// Require specific role (throws AccessDeniedException if missing)
Auth.requireRole("ADMIN");

// Execute as another user (useful for testing)
Auth.runAs(adminUser, () -> {
    // Code runs with adminUser context
    return someService.doAdminStuff();
});
```

### Password Operations with `Auth`

```java
// Hash a password
String hash = Auth.hashPassword("myPassword123");

// Verify password
boolean valid = Auth.checkPassword("myPassword123", hash);
```

### `Guard` Facade

The `Guard` facade provides declarative authorization checks with automatic exception throwing.

```java
// Role checks - throws AccessDeniedException if fails
Guard.role("ADMIN");
Guard.anyRole("ADMIN", "MANAGER");
Guard.allRoles("VERIFIED", "PREMIUM");
Guard.admin();

// Ownership checks - admin bypass by default
Guard.owner(resourceOwnerId);
Guard.ownerOr(resourceOwnerId, "SUPPORT"); // Owner OR has SUPPORT role

// Conditional checks
Guard.when(user.isActive(), "User account is inactive");
Guard.authenticated(); // Throws UnauthorizedException if not authenticated
Guard.guest(); // Throws AccessDeniedException if already authenticated

// Fluent API for complex checks
Guard.check()
    .role("USER")
    .owner(resourceOwnerId)
    .when(resource.isPublished(), "Resource not published")
    .authorize();

// OR logic in fluent API
Guard.check()
    .role("ADMIN")
    .or()
    .owner(resourceOwnerId)
    .authorize(); // Passes if ADMIN OR owner
```

---

## Utility Classes

### `LazyAuth`

Convenient utility methods for security checks.

```java
// Authentication checks
LazyAuth.isAuthenticated();
LazyAuth.isAnonymous();

// Get user info
LazyUser user = LazyAuth.user();
String userId = LazyAuth.userId();
String username = LazyAuth.username();

// Role and permission checks
LazyAuth.hasRole("ADMIN");
LazyAuth.hasAnyRole("ADMIN", "MANAGER");
LazyAuth.hasAllRoles("VERIFIED", "PREMIUM");
LazyAuth.hasPermission("posts:write");
LazyAuth.isAdmin();

// Conditional execution
LazyAuth.ifAuthenticated(() -> log.info("User logged in"));
LazyAuth.ifRole("ADMIN", () -> showAdminPanel());
LazyAuth.ifAdmin(() -> enableAdminFeatures());

// Get value conditionally
String greeting = LazyAuth.ifAuthenticated(
    () -> "Hello, " + LazyAuth.username(),
    "Hello, Guest"
);
```

### `LazySecurityContext`

Thread-safe access to the current security context.

```java
// Get current user (never null - returns anonymous if not authenticated)
LazyUser user = LazySecurityContext.getCurrentUser();

// Get as Optional (empty if not authenticated)
Optional<LazyUser> optUser = LazySecurityContext.getUser();

// Direct checks
LazySecurityContext.isAuthenticated();
LazySecurityContext.getUserId();
LazySecurityContext.getUsername();
LazySecurityContext.hasRole("ADMIN");
LazySecurityContext.hasAnyRole("ADMIN", "MANAGER");
LazySecurityContext.hasAllRoles("VERIFIED", "PREMIUM");
LazySecurityContext.hasPermission("posts:write");
LazySecurityContext.isAdmin();

// Execute code as another user (useful for tests)
LazySecurityContext.runAs(testUser, () -> {
    // Code executes with testUser context
    myService.doSomething();
});

// With return value
String result = LazySecurityContext.runAs(adminUser, () -> {
    return adminService.getSecretData();
});
```

### `PasswordUtils`

BCrypt password hashing utilities (OWASP recommended).

```java
// Hash a password
String hash = PasswordUtils.hash("myPassword123");

// Verify password
boolean matches = PasswordUtils.matches("myPassword123", hash);

// Get encoder for Spring Security configuration
PasswordEncoder encoder = PasswordUtils.encoder();
```

---

## LazyUser

The `LazyUser` class represents the authenticated user and is automatically injected into controller methods.

```java
@GetMapping("/profile")
@Authenticated
public Profile getProfile(LazyUser user) {
    // LazyUser is automatically injected
    String id = user.getId();
    String username = user.getUsername();
    Set<String> roles = user.getRoles();
    Set<String> permissions = user.getPermissions();
    boolean authenticated = user.isAuthenticated();
    
    // Role checks
    user.hasRole("ADMIN");
    user.hasAnyRole("ADMIN", "MANAGER");
    user.hasAllRoles("VERIFIED", "PREMIUM");
    user.isAdmin();
    
    // Permission checks
    user.hasPermission("posts:write");
    
    // Access JWT claims
    String department = user.getClaim("department");
    Integer level = user.getClaim("level", 1); // with default
    boolean hasClaim = user.hasClaim("customField");
    
    return profileService.getByUserId(id);
}

// Create user programmatically
LazyUser user = LazyUser.builder()
    .id("123")
    .username("john.doe")
    .roles("USER", "PREMIUM")
    .permissions("posts:read", "posts:write")
    .claim("department", "Engineering")
    .claim("level", 5)
    .authenticated(true)
    .build();

// Anonymous user
LazyUser anonymous = LazyUser.anonymous();
```

---

## JWT Authentication

### JwtService

High-level service for JWT operations.

```java
@RestController
@RequestMapping("/api/auth")
@Public
public class AuthController {

    private final JwtService jwtService;
    private final UserService userService;

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        User user = userService.authenticate(request.username(), request.password());
        
        LazyUser lazyUser = LazyUser.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles(user.getRoles())
            .build();
        
        TokenPair tokens = jwtService.createTokens(lazyUser);
        return tokens.toMap();
    }

    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody RefreshRequest request) {
        TokenPair tokens = jwtService.refresh(request.refreshToken());
        return tokens.toMap();
    }
}
```

### TokenPair

Result of token generation containing access and refresh tokens.

```java
TokenPair tokens = jwtService.createTokens(user);

String accessToken = tokens.accessToken();
String refreshToken = tokens.refreshToken();
long expiresIn = tokens.expiresIn();
String tokenType = tokens.tokenType(); // "Bearer"

// Convert to response map
Map<String, Object> response = tokens.toMap();
// {
//   "access_token": "eyJ...",
//   "refresh_token": "eyJ...",
//   "expires_in": 86400,
//   "token_type": "Bearer"
// }
```

### JwtProvider (Low-level)

For advanced JWT operations, inject `JwtProvider` directly.

```java
@Autowired
private JwtProvider jwtProvider;

// Generate tokens
String accessToken = jwtProvider.generateToken(user);
String accessTokenWithClaims = jwtProvider.generateToken(user, Map.of("custom", "value"));
String refreshToken = jwtProvider.generateRefreshToken(user);

// Validate and parse
boolean isValid = jwtProvider.isTokenValid(token);
LazyUser user = jwtProvider.validateToken(token);
String subject = jwtProvider.extractSubject(token);
```

---

## Advanced Configuration

### Full @EnableLazySecurity Options

```java
@EnableLazySecurity(
    // JWT Configuration
    jwt = @JwtConfig(
        secret = "${JWT_SECRET}",
        expiration = 86400000,       // 24 hours
        refreshExpiration = 604800000, // 7 days
        header = "Authorization",
        prefix = "Bearer "
    ),
    
    // Public paths (no authentication required)
    publicPaths = {
        "/api/auth/**",
        "/api/public/**", 
        "/health",
        "/actuator/**",
        "/swagger-ui/**",
        "/v3/api-docs/**"
    },
    
    // Default role for authenticated users
    defaultRole = "USER",
    
    // CORS configuration
    corsEnabled = true,
    corsOrigins = {"http://localhost:3000", "https://myapp.com"},
    corsMethods = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
    corsHeaders = {"*"},
    
    // CSRF (usually disabled for REST APIs)
    csrfEnabled = false,
    
    // HTTPS-only paths
    securePaths = {"/api/payments/**"},
    
    // Debug mode
    debug = false
)
@SpringBootApplication
public class MyApplication { }
```

### Configuration via application.yml

```yaml
lazy-security:
  enabled: true
  debug: false
  
  public-paths:
    - /api/public/**
    - /health
    - /actuator/**
  
  jwt:
    secret: ${JWT_SECRET}
    expiration: 86400000      # 24 hours in ms
    refresh-expiration: 604800000  # 7 days in ms
    issuer: my-app
  
  cors:
    enabled: true
    allowed-origins:
      - http://localhost:3000
      - https://myapp.com
    allowed-methods:
      - GET
      - POST
      - PUT
      - DELETE
    allowed-headers:
      - "*"
    allow-credentials: true
    max-age: 3600
  
  csrf:
    enabled: false
```

---

## Exception Handling

LSS provides automatic exception handling with proper HTTP responses:

| Exception | HTTP Status | Description |
|-----------|-------------|-------------|
| `UnauthorizedException` | 401 | Authentication required |
| `AccessDeniedException` | 403 | Insufficient permissions |
| `RateLimitExceededException` | 429 | Too many requests |

```java
// Throw manually when needed
throw new UnauthorizedException("Please log in");
throw new AccessDeniedException("Admin access required");
throw new RateLimitExceededException("Rate limit exceeded");
```

---

## LazySpringSecurity vs Spring Security

| Feature | Spring Security | LazySpringSecurity |
|---------|-----------------|-------------------|
| Configuration | Complex Java config | Simple annotations + YAML |
| Learning Curve | Steep | Minimal |
| Boilerplate | High | Almost none |
| JWT Support | Manual setup | Built-in |
| Readability | Low | High |
| Flexibility | Very High | High |
| Method Security | `@PreAuthorize("hasRole('ADMIN')")` | `@Admin` or `@LazySecured(roles = "ADMIN")` |
| Public Endpoints | Complex matcher config | `@Public` |
| User Access | `SecurityContextHolder.getContext()...` | `Auth.user()` or inject `LazyUser` |
| Rate Limiting | Manual implementation | `@RateLimit` annotation |

### Before (Spring Security)

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
    
    // Plus JwtAuthFilter, UserDetailsService, PasswordEncoder, etc...
}
```

### After (LazySpringSecurity)

```java
@SpringBootApplication
@EnableLazySecurity(
    jwt = @JwtConfig(secret = "${JWT_SECRET}"),
    publicPaths = {"/api/public/**"}
)
public class MyApp { }

// That's it! Use @Public, @Admin, @LazySecured, @Authenticated on your endpoints
```

---

## Complete Example

### Auth Controller

```java
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JwtService jwtService;
    private final UserService userService;

    @Public
    @PostMapping("/register")
    public Map<String, Object> register(@RequestBody RegisterRequest request) {
        // Hash password
        String hashedPassword = Auth.hashPassword(request.password());
        
        // Create user
        User user = userService.create(request.username(), hashedPassword);
        
        // Generate tokens
        LazyUser lazyUser = LazyUser.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles("USER")
            .build();
        
        return jwtService.createTokens(lazyUser).toMap();
    }

    @Public
    @RateLimit(requests = 5, window = 300, key = "ip")
    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody LoginRequest request) {
        User user = userService.findByUsername(request.username())
            .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));
        
        if (!Auth.checkPassword(request.password(), user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials");
        }
        
        LazyUser lazyUser = LazyUser.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles(user.getRoles())
            .build();
        
        return jwtService.createTokens(lazyUser).toMap();
    }

    @Public
    @PostMapping("/refresh")
    public Map<String, Object> refresh(@RequestBody RefreshRequest request) {
        return jwtService.refresh(request.refreshToken()).toMap();
    }

    @Authenticated
    @GetMapping("/me")
    public LazyUser me(LazyUser user) {
        return user;
    }
}
```

### Protected Controller

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @Authenticated
    @GetMapping
    public List<User> listUsers() {
        return userService.findAll();
    }

    @Owner(field = "userId", adminBypass = true)
    @GetMapping("/{userId}")
    public User getUser(@PathVariable String userId) {
        return userService.findById(userId);
    }

    @Owner(field = "userId", adminBypass = true)
    @PutMapping("/{userId}")
    public User updateUser(@PathVariable String userId, @RequestBody User user) {
        return userService.update(userId, user);
    }

    @Admin
    @DeleteMapping("/{userId}")
    public void deleteUser(@PathVariable String userId) {
        userService.delete(userId);
    }
}
```

### Using Guard in Service Layer

```java
@Service
public class OrderService {

    public Order getOrder(String orderId) {
        Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NotFoundException("Order not found"));
        
        // Only owner or admin can view
        Guard.ownerOr(order.getUserId(), "ADMIN");
        
        return order;
    }

    public void cancelOrder(String orderId) {
        Order order = orderRepository.findById(orderId)
            .orElseThrow(() -> new NotFoundException("Order not found"));
        
        // Complex authorization logic
        Guard.check()
            .owner(order.getUserId())
            .when(order.getStatus() != OrderStatus.SHIPPED, "Cannot cancel shipped orders")
            .or()
            .role("ADMIN")
            .authorize();
        
        order.setStatus(OrderStatus.CANCELLED);
        orderRepository.save(order);
    }
}
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Contributing

Contributions are welcome! Please read our contributing guidelines first.

---

Made by Sudojed Team
