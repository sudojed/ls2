# LazySpringSecurity (LSS)

**Annotation-driven security framework for Spring Boot applications**

[![JitPack](https://jitpack.io/v/jedin01/ls2.svg)](https://jitpack.io/#jedin01/ls2)

LazySpringSecurity simplifies Spring Security configuration by using annotations to define endpoint security directly in your controllers. No manual configuration files, no complex setup - just clean, readable security annotations.

## Features

### Core Security Annotations
- **@Public** - Mark endpoints as publicly accessible
- **@Secured** - Require authentication with optional role-based access
- **@Register** - Auto-generate user registration endpoints
- **@Login** - Auto-generate authentication endpoints  
- **@RefreshToken** - Auto-generate token refresh endpoints

### Advanced Security Annotations
- **@Owner** - Resource ownership verification (user can only access their own data)
- **@RateLimit** - Request rate limiting and abuse prevention
- **@Audit** - Automatic security event logging and tracking
- **@Cached** - Security-aware intelligent response caching

### Key Features
- **JWT Token Management** - Automatic token generation, validation, and refresh
- **Role-Based Access Control** - Fine-grained permission system
- **Automatic Endpoint Discovery** - Zero manual configuration needed
- **Meta-Annotation Support** - @Register/@Login/@RefreshToken inherit @Public automatically
- **Ownership Verification** - Built-in resource ownership checking
- **Performance Optimization** - Rate limiting and intelligent caching

## Quick Start

### 1. Add Dependency

**Maven:**
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.jedin01</groupId>
    <artifactId>ls2</artifactId>
    <version>v1.0.0</version>
</dependency>
```

**Gradle:**
```gradle
repositories {
    maven { url 'https://jitpack.io' }
}
implementation 'com.github.jedin01:ls2:v1.0.0'
```

### 2. Enable LSS

```java
@SpringBootApplication
@EnableLazySecurity(
    jwt = @JwtConfig(
        secret = "${JWT_SECRET:your-secret-key}",
        expiration = 3600000,
        refreshExpiration = 86400000
    )
)
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### 3. Secure Your Endpoints

```java
@RestController
@RequestMapping("/api")
public class ApiController {
    
    // Public endpoint - no authentication required
    @Public
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }
    
    // Protected endpoint - authentication required
    @Secured
    @GetMapping("/profile")
    public ResponseEntity<User> getProfile() {
        // Implementation here
        return ResponseEntity.ok(user);
    }
    
    // Admin only endpoint
    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        // Implementation here
        return ResponseEntity.noContent().build();
    }
    
    // Multiple roles allowed
    @Secured({"ADMIN", "MANAGER"})
    @PostMapping("/reports")
    public ResponseEntity<Report> createReport(@RequestBody ReportRequest request) {
        // Implementation here
        return ResponseEntity.ok(report);
    }
    
    // Ownership verification - users can only access their own data
    @Owner(field = "userId")
    @GetMapping("/users/{userId}/profile")
    public ResponseEntity<UserProfile> getUserProfile(@PathVariable String userId) {
        // Implementation here - automatically verifies userId matches current user
        return ResponseEntity.ok(userProfile);
    }
    
    // Rate limiting
    @RateLimit(requests = 10, windowInSeconds = 60)
    @PostMapping("/api/contact")
    public ResponseEntity<String> submitContactForm(@RequestBody ContactRequest request) {
        // Implementation here - max 10 requests per minute
        return ResponseEntity.ok("Message sent");
    }
    
    // Audit logging for sensitive operations
    @Audit(action = "USER_DELETE", level = Audit.AuditLevel.HIGH)
    @Secured("ADMIN")
    @DeleteMapping("/admin/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        // Implementation here - automatically logged
        return ResponseEntity.noContent().build();
    }
    
    // Response caching
    @Cached(ttl = 300, key = "user-stats")
    @Public
    @GetMapping("/api/statistics")
    public ResponseEntity<Statistics> getStatistics() {
        // Implementation here - cached for 5 minutes
        return ResponseEntity.ok(statistics);
    }
}
```

## Authentication Endpoints

LSS can auto-generate authentication endpoints using annotations:

```java
@RestController
@RequestMapping("/auth")
public class AuthController {
    
    // Auto-generated registration endpoint
    @Register(
        userService = UserService.class,
        createMethod = "createUser",
        existsMethod = "findByUsername"
    )
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        return null; // Implementation generated automatically
    }
    
    // Auto-generated login endpoint
    @Login(
        userService = UserService.class,
        findMethod = "findByUsername"
    )
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return null; // Implementation generated automatically
    }
    
    // Auto-generated token refresh endpoint
    @RefreshToken
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        return null; // Implementation generated automatically
    }
}
```

## User Service Integration

Your UserService needs to implement the methods referenced in the annotations:

```java
@Service
public class UserService {
    
    // For @Register annotation
    public User createUser(String username, String email, String password) {
        // Hash password and create user
        String hashedPassword = Auth.hashPassword(password);
        User user = new User(username, email, hashedPassword);
        // Save and return user
        return userRepository.save(user);
    }
    
    // For @Login annotation  
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    // Other finder methods as needed
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}
```

## Configuration Options

### JWT Configuration
```java
@JwtConfig(
    secret = "${JWT_SECRET}",           // JWT signing secret
    expiration = 3600000,               // Access token expiration (1 hour)
    refreshExpiration = 86400000,       // Refresh token expiration (24 hours)  
    header = "Authorization",           // Token header name
    prefix = "Bearer ",                 // Token prefix
    issuer = "my-app"                  // Token issuer
)
```

### Security Configuration
```java
@EnableLazySecurity(
    jwt = @JwtConfig(...),
    defaultRole = "USER",               // Default role for authenticated users
    csrfEnabled = false,                // CSRF protection (default: false for APIs)
    corsEnabled = true,                 // CORS configuration
    corsOrigins = {"http://localhost:3000", "https://myapp.com"}
)
```

## Annotation Reference

### @Public
Makes an endpoint publicly accessible without authentication.

```java
@Public
@GetMapping("/api/status")
public String getStatus() { return "OK"; }
```

### @Secured
Requires authentication. Optionally specify required roles.

```java
// Any authenticated user
@Secured
@GetMapping("/api/profile")
public User getProfile() { ... }

// Specific role required
@Secured("ADMIN")
@DeleteMapping("/api/admin/users/{id}")
public void deleteUser(@PathVariable String id) { ... }

// Multiple roles (any of them)
@Secured({"ADMIN", "MANAGER"}) 
@GetMapping("/api/reports")
public List<Report> getReports() { ... }
```

### @Register
Auto-generates user registration logic.

```java
@Register(
    userService = UserService.class,
    createMethod = "createUser",
    existsMethod = "findByUsername",
    requestFields = {"username", "email", "password"},
    uniqueField = "username",
    autoLogin = false
)
```

### @Login  
Auto-generates authentication logic.

```java
@Login(
    userService = UserService.class,
    findMethod = "findByUsername",
    claims = {"email", "displayName"},
    includeUserInfo = true
)
```

### @RefreshToken
Auto-generates token refresh logic.

```java
@RefreshToken(
    tokenField = "refresh_token"
)
```

### @Owner
Validates resource ownership - users can only access their own data.

```java
// Path variable ownership
@Owner(field = "userId")
@GetMapping("/users/{userId}/orders")
public List<Order> getUserOrders(@PathVariable String userId) { ... }

// Entity ownership verification
@Owner(entityField = "createdBy")
@GetMapping("/posts/{id}")
public Post getPost(@PathVariable Long id) { ... }

// With admin bypass
@Owner(field = "userId", adminBypass = true)
@PutMapping("/users/{userId}")
public User updateUser(@PathVariable String userId, @RequestBody User user) { ... }
```

### @RateLimit
Prevents abuse with request rate limiting.

```java
// 100 requests per 60 seconds per IP
@RateLimit(requests = 100, windowInSeconds = 60)
@PostMapping("/api/upload")
public ResponseEntity<?> uploadFile(@RequestParam MultipartFile file) { ... }

// Per-user rate limiting
@RateLimit(requests = 5, windowInSeconds = 60, perUser = true)
@PostMapping("/api/send-email")
public ResponseEntity<?> sendEmail(@RequestBody EmailRequest request) { ... }
```

### @Audit
Automatic logging of security-sensitive operations.

```java
@Audit(action = "USER_LOGIN", level = Audit.AuditLevel.MEDIUM)
@PostMapping("/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) { ... }

@Audit(action = "DATA_DELETE", level = Audit.AuditLevel.HIGH, 
       includeRequest = true, includeResponse = false)
@Secured("ADMIN")
@DeleteMapping("/admin/data/{id}")
public ResponseEntity<?> deleteData(@PathVariable String id) { ... }
```

### @Cached
Security-aware response caching for improved performance.

```java
// Cache for 5 minutes with automatic key generation
@Cached(ttl = 300)
@Public
@GetMapping("/api/public-data")
public ResponseEntity<?> getPublicData() { ... }

// Per-user caching
@Cached(ttl = 600, perUser = true)
@Secured
@GetMapping("/api/user-dashboard")
public ResponseEntity<?> getUserDashboard() { ... }

// Custom cache key
@Cached(ttl = 1800, key = "stats-${#category}")
@Public
@GetMapping("/api/stats/{category}")
public ResponseEntity<?> getStatistics(@PathVariable String category) { ... }
```

## Key Benefits

### Zero Configuration
No need for manual `publicPaths` configuration. LSS automatically detects `@Public` and `@Secured` annotations and configures Spring Security accordingly.

**Before (Manual Configuration):**
```java
@EnableLazySecurity(
    jwt = @JwtConfig(secret = "..."),
    publicPaths = {"/api/health", "/api/public/**", "/auth/**"}
)
```

**After (Automatic Detection):**
```java
@EnableLazySecurity(jwt = @JwtConfig(secret = "..."))
// publicPaths automatically detected from @Public annotations
```

### Self-Documenting
Security requirements are visible directly in controller code, making it easy to understand what authentication is required for each endpoint.

### Maintainable
No duplicate configuration between annotations and manual path lists. Security configuration lives with the endpoint definition.

## Example Application Structure

```
src/main/java/com/example/
├── Application.java                    # @EnableLazySecurity
├── controller/
│   ├── AuthController.java             # @Register, @Login, @RefreshToken
│   ├── UserController.java             # @Secured with roles
│   └── PublicController.java           # @Public endpoints
├── service/
│   └── UserService.java                # User management logic
├── model/
│   └── User.java                       # User entity
└── dto/
    ├── LoginRequest.java
    └── RegisterRequest.java
```

## Testing

LSS provides utilities for testing secured endpoints:

```java
@TestMethodOrder(OrderAnnotation.class)
class SecurityTest {
    
    @Test
    @Order(1)
    void testPublicEndpoint() {
        // Test @Public endpoints
        mockMvc.perform(get("/api/health"))
            .andExpect(status().isOk());
    }
    
    @Test  
    @Order(2)
    void testProtectedEndpointWithoutAuth() {
        // Test @Secured endpoints without token
        mockMvc.perform(get("/api/profile"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    @Order(3) 
    void testLoginAndProtectedAccess() {
        // Test login and use token
        String token = // login and extract token
        
        mockMvc.perform(get("/api/profile")
            .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
}
```

## Documentation

- [Demo Project](demo-project/) - Complete working example
- [Test Scripts](test-registration.sh) - Automated testing with curl
- [Migration Guide](RESOLVED_ISSUES.md) - Upgrading from manual configuration

## Requirements

- Java 17+
- Spring Boot 3.0+
- Spring Security 6.0+

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**LazySpringSecurity - Security annotations that just work**