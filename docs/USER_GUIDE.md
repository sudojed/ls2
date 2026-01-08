# LazySpringSecurity (LSS) - User Guide

> **Complete guide for developers using LazySpringSecurity in production applications**

## Table of Contents

1. [Quick Start](#quick-start)
2. [Configuration](#configuration)
3. [Security Annotations](#security-annotations)
4. [Authentication](#authentication)
5. [Authorization](#authorization)
6. [JWT Management](#jwt-management)
7. [Advanced Features](#advanced-features)
8. [Best Practices](#best-practices)
9. [Troubleshooting](#troubleshooting)
10. [Migration Guide](#migration-guide)

## Quick Start

### 1. Add Dependency

**Maven:**
```xml
<dependency>
    <groupId>ao.sudojed</groupId>
    <artifactId>lazy-spring-security</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

**Gradle:**
```gradle
implementation 'ao.sudojed:lazy-spring-security:1.0.0-SNAPSHOT'
```

### 2. Enable LazySpringSecurity

```java
@SpringBootApplication
@EnableLazySecurity
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
```

### 3. Configure JWT Secret

**application.properties:**
```properties
lazy-security.jwt.secret=your-very-secure-256-bit-secret-key-here-change-this-in-production
```

**application.yml:**
```yaml
lazy-security:
  jwt:
    secret: ${JWT_SECRET:your-very-secure-256-bit-secret-key-here-change-this-in-production}
```

### 4. Secure Your Endpoints

```java
@RestController
@RequestMapping("/api")
public class UserController {

    @Public
    @GetMapping("/health")
    public String health() {
        return "OK";
    }

    @Secured
    @GetMapping("/profile")
    public User getProfile(LazyUser user) {
        return userService.findById(user.getId());
    }

    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
}
```

That's it! Your application is now secured with JWT authentication and role-based authorization.

## Configuration

### Basic Configuration

**Minimal Configuration (application.properties):**
```properties
# JWT Secret (REQUIRED) - Must be at least 32 characters
lazy-security.jwt.secret=your-very-secure-256-bit-secret-key-here-change-this-in-production

# Public endpoints (optional)
lazy-security.public-paths[0]=/auth/**
lazy-security.public-paths[1]=/health

# CORS for frontend integration (optional)
lazy-security.cors.enabled=true
lazy-security.cors.allowed-origins[0]=http://localhost:3000
```

### Complete Configuration

**application.yml:**
```yaml
lazy-security:
  # Framework settings
  enabled: true
  debug: false
  default-role: USER
  default-mode: authenticated

  # Public endpoints (no authentication required)
  public-paths:
    - /auth/**
    - /health
    - /actuator/health
    - /docs/**
    - /error

  # JWT Configuration
  jwt:
    secret: ${JWT_SECRET:your-secret-key}
    expiration: 24h
    refresh-expiration: 7d
    refresh-enabled: true
    issuer: my-app
    header: Authorization
    prefix: "Bearer "

  # CORS Configuration
  cors:
    enabled: true
    allowed-origins:
      - http://localhost:3000
      - https://yourdomain.com
    allowed-methods:
      - GET
      - POST
      - PUT
      - DELETE
      - OPTIONS
    allowed-headers:
      - "*"
    allow-credentials: true
    max-age: 3600

  # CSRF (typically disabled for REST APIs)
  csrf:
    enabled: false
```

### Environment-based Configuration

**Production application.yml:**
```yaml
lazy-security:
  debug: false
  jwt:
    secret: ${JWT_SECRET}  # Required environment variable
    expiration: 1h         # Shorter for better security
    refresh-expiration: 24h
  cors:
    allowed-origins:
      - https://${FRONTEND_DOMAIN}
      - https://www.${FRONTEND_DOMAIN}

# Required environment variables:
# JWT_SECRET=your-production-secret-key
# FRONTEND_DOMAIN=yourdomain.com
```

## Security Annotations

### @Secured - Unified Authorization

The `@Secured` annotation is the cornerstone of LazySpringSecurity authorization.

#### Basic Authentication (Any Authenticated User)
```java
@Secured
@GetMapping("/profile")
public User getProfile() {
    return userService.getCurrentUser();
}
```

#### Single Role Requirement
```java
@Secured("ADMIN")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) {
    userService.delete(id);
}
```

#### Multiple Roles (OR Logic - Default)
```java
@Secured({"ADMIN", "MANAGER"})
@GetMapping("/reports")
public List<Report> getReports() {
    return reportService.generateReports();
}
```

#### Multiple Roles (AND Logic)
```java
@Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
@GetMapping("/exclusive-content")
public Content getExclusiveContent() {
    return contentService.getPremiumContent();
}
```

#### Permission-Based Authorization
```java
@Secured(permissions = {"users:write", "admin:manage"})
@PostMapping("/users")
public User createUser(@RequestBody CreateUserRequest request) {
    return userService.create(request);
}
```

#### SpEL Conditions
```java
@Secured(condition = "#userId == principal.id or hasRole('ADMIN')")
@GetMapping("/users/{userId}/orders")
public List<Order> getUserOrders(@PathVariable String userId) {
    return orderService.findByUserId(userId);
}
```

#### Custom Error Messages
```java
@Secured(value = "ADMIN", message = "Administrator access required for user management")
@PostMapping("/users/{id}/roles")
public void addRole(@PathVariable String id, @RequestBody AddRoleRequest request) {
    userService.addRole(id, request.getRole());
}
```

#### Class-Level Security
```java
@Secured("ADMIN")
@RestController
@RequestMapping("/api/admin")
public class AdminController {
    // All endpoints require ADMIN role by default
    
    @GetMapping("/users")
    public List<User> getUsers() { }
    
    @Secured({"ADMIN", "MANAGER"}) // Override class-level requirement
    @GetMapping("/reports")
    public List<Report> getReports() { }
}
```

### @Public - Public Access

Marks endpoints as publicly accessible (no authentication required).

```java
@Public
@GetMapping("/health")
public String health() {
    return "OK";
}

@Public
@GetMapping("/docs")
public String documentation() {
    return "API Documentation";
}
```

### @Owner - Resource Ownership

Validates that the current user owns the resource being accessed.

#### Basic Ownership Check
```java
@Owner(field = "userId")
@GetMapping("/users/{userId}/profile")
public UserProfile getUserProfile(@PathVariable String userId) {
    return userService.getProfile(userId);
}
```

#### Custom Bypass Roles
```java
@Owner(field = "userId", bypassRoles = {"ADMIN", "SUPPORT"})
@PutMapping("/users/{userId}")
public User updateUser(@PathVariable String userId, @RequestBody UpdateUserRequest request) {
    return userService.update(userId, request);
}
```

#### Request Body Field Validation
```java
@Owner(requestField = "authorId")
@PostMapping("/posts")
public Post createPost(@RequestBody CreatePostRequest request) {
    // Validates that request.authorId == currentUser.id
    return postService.create(request);
}
```

### @RateLimit - Request Throttling

Protects endpoints from abuse and DDoS attacks.

#### Basic Rate Limiting
```java
@RateLimit(requests = 100, window = 60) // 100 requests per minute
@PostMapping("/api/data")
public Response processData(@RequestBody DataRequest request) {
    return dataService.process(request);
}
```

#### Per-User Rate Limiting
```java
@RateLimit(requests = 10, window = 60, perUser = true)
@PostMapping("/messages")
public Message sendMessage(@RequestBody MessageRequest request) {
    return messageService.send(request);
}
```

#### Login Protection
```java
@RateLimit(requests = 5, window = 300, key = "ip") // 5 attempts per 5 min per IP
@PostMapping("/login")
public TokenResponse login(@RequestBody LoginRequest request) {
    return authService.authenticate(request);
}
```

### @Audit - Security Event Logging

Automatically logs security-related events for compliance and monitoring.

#### Basic Audit Logging
```java
@Audit
@Secured("ADMIN")
@DeleteMapping("/users/{id}")
public void deleteUser(@PathVariable Long id) {
    userService.delete(id);
}
```

#### Custom Audit Configuration
```java
@Audit(
    action = "PASSWORD_RESET",
    level = AuditLevel.SENSITIVE,
    includeParams = true,
    excludeParams = {"password", "newPassword"}
)
@PostMapping("/users/{id}/reset-password")
public void resetPassword(@PathVariable Long id, @RequestBody PasswordResetRequest request) {
    userService.resetPassword(id, request);
}
```

### @Cached - Security-Aware Caching

Provides security-aware response caching that respects user context.

#### Per-User Caching
```java
@Cached(ttl = 300) // Cache for 5 minutes per user
@Secured
@GetMapping("/profile")
public UserProfile getProfile() {
    return userService.getCurrentProfile();
}
```

#### Global Caching for Public Data
```java
@Cached(ttl = 600, perUser = false) // Global cache for 10 minutes
@Public
@GetMapping("/products")
public List<Product> getProducts() {
    return productService.findAll();
}
```

#### Role-Based Caching
```java
@Cached(ttl = 120, perRole = true) // Cache per role for 2 minutes
@Secured({"ADMIN", "MANAGER"})
@GetMapping("/reports")
public List<Report> getReports() {
    return reportService.generate();
}
```

## Authentication

### Authentication Endpoints

LazySpringSecurity provides powerful annotations to create authentication endpoints with zero boilerplate.

#### @Login - User Authentication
```java
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Login(userService = UserService.class)
    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        // Implementation is handled automatically
        // Validates credentials and returns JWT tokens
    }
}
```

**Advanced Login Configuration:**
```java
@Login(
    userService = UserService.class,
    findMethod = "findByEmail",           // Custom user lookup method
    usernameField = "email",              // Database field for username
    passwordField = "passwordHash",       // Database field for password
    rolesField = "authorities",           // Database field for roles
    requestUsernameField = "email",       // Request JSON field for username
    requestPasswordField = "password",    // Request JSON field for password
    includeUserInfo = true,               // Include user details in response
    claims = {"email", "firstName"},      // Additional JWT claims
    invalidCredentialsMessage = "Invalid email or password"
)
@PostMapping("/login")
public TokenResponse login(@RequestBody LoginRequest request) { }
```

#### @Register - User Registration
```java
@Register(userService = UserService.class)
@PostMapping("/register")
public UserResponse register(@RequestBody RegisterRequest request) {
    // Automatically creates user with validation
    // Checks for existing users
    // Returns user details (optionally with tokens if autoLogin=true)
}
```

**Advanced Register Configuration:**
```java
@Register(
    userService = UserService.class,
    createMethod = "createUser",          // Custom user creation method
    existsMethod = "findByEmail",         // Method to check existing users
    requestFields = {"email", "password", "firstName"}, // Required fields
    uniqueField = "email",                // Field that must be unique
    autoLogin = true,                     // Automatically login after registration
    existsMessage = "Email already in use",
    responseFields = {"id", "email", "firstName"} // Fields in response
)
@PostMapping("/register")
public UserResponse register(@RequestBody RegisterRequest request) { }
```

#### @RefreshToken - Token Refresh
```java
@RefreshToken
@PostMapping("/refresh")
public TokenResponse refresh(@RequestBody RefreshTokenRequest request) {
    // Automatically handles refresh token validation
    // Generates new access token
}
```

### Manual JWT Operations

For custom authentication flows:

```java
@RestController
public class CustomAuthController {

    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserService userService;

    @PostMapping("/custom-login")
    public TokenResponse customLogin(@RequestBody LoginRequest request) {
        // Custom validation logic
        User user = userService.authenticate(request.getUsername(), request.getPassword());
        
        if (user == null) {
            throw new UnauthorizedException("Invalid credentials");
        }

        // Create LazyUser
        LazyUser lazyUser = LazyUser.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles(user.getRoles())
            .permissions(user.getPermissions())
            .claim("email", user.getEmail())
            .claim("department", user.getDepartment())
            .build();

        // Generate tokens
        TokenPair tokens = jwtService.createTokens(lazyUser);
        
        return new TokenResponse(
            tokens.accessToken(),
            tokens.refreshToken(),
            "Bearer",
            tokens.expiresIn()
        );
    }
}
```

## Authorization

### Declarative Authorization (Annotations)

Use annotations for method-level security:

```java
@RestController
public class UserController {

    // Any authenticated user
    @Secured
    @GetMapping("/profile")
    public User getProfile() { }

    // Specific role required
    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) { }

    // Multiple roles (OR logic)
    @Secured({"ADMIN", "MANAGER"})
    @GetMapping("/reports")
    public List<Report> getReports() { }

    // Multiple roles (AND logic)
    @Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
    @GetMapping("/premium-content")
    public Content getPremiumContent() { }

    // Permission-based
    @Secured(permissions = "users:delete")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) { }

    // Custom SpEL condition
    @Secured(condition = "#id == principal.id or hasRole('ADMIN')")
    @GetMapping("/users/{id}")
    public User getUser(@PathVariable String id) { }
}
```

### Imperative Authorization (Facades)

Use facades for programmatic security checks:

#### Auth Facade - User Information
```java
@Service
public class UserService {

    public void updateProfile(UpdateProfileRequest request) {
        // Access current user information
        String userId = Auth.id();
        String username = Auth.username();
        boolean isAdmin = Auth.isAdmin();
        String email = Auth.claim("email");
        
        // Get full user object
        LazyUser user = Auth.user();
        Set<String> roles = user.getRoles();
        
        // Password operations
        String hashedPassword = Auth.hashPassword(request.getNewPassword());
        boolean isValidPassword = Auth.checkPassword(request.getCurrentPassword(), user.getPasswordHash());
        
        if (!isValidPassword) {
            throw new UnauthorizedException("Current password is incorrect");
        }
        
        // Update logic...
    }
}
```

#### Guard Facade - Authorization Checks
```java
@Service
public class AdminService {

    public void deleteUser(String userId) {
        // Simple authorization checks (throws AccessDeniedException if fails)
        Guard.admin();                           // Requires ADMIN role
        Guard.role("USER_MANAGER");             // Requires specific role
        Guard.anyRole("ADMIN", "SUPER_ADMIN");  // Requires any of these roles
        Guard.owner(userId);                    // Ownership check with admin bypass
        
        // Fluent authorization API
        Guard.check()
            .role("ADMIN")
            .permission("users:delete")
            .authorize();
        
        userRepository.delete(userId);
    }

    public Data getSensitiveData() {
        // Complex authorization logic
        Guard.check()
            .authenticated()
            .anyRole("ADMIN", "ANALYST")
            .permission("data:read")
            .condition(() -> isBusinessHours())
            .authorize();
        
        return dataService.getSensitiveData();
    }
}
```

### User Information Access

#### Method Parameter Injection
```java
@RestController
public class ProfileController {

    @Secured
    @GetMapping("/profile")
    public UserResponse getProfile(LazyUser user) {
        // LazyUser automatically injected
        return UserResponse.builder()
            .id(user.getId())
            .username(user.getUsername())
            .roles(user.getRoles())
            .email(user.getClaim("email"))
            .build();
    }
}
```

#### Security Context Access
```java
@Service
public class AuditService {

    public void logUserAction(String action) {
        LazyUser user = LazySecurityContext.getCurrentUser();
        
        if (user.isAuthenticated()) {
            auditRepository.save(new AuditLog(
                user.getId(),
                user.getUsername(),
                action,
                Instant.now()
            ));
        }
    }
}
```

## JWT Management

### Token Structure

LazySpringSecurity generates JWT tokens with the following structure:

```json
{
  "sub": "user-id",
  "username": "john.doe", 
  "roles": ["USER", "ADMIN"],
  "permissions": ["users:read", "posts:write"],
  "custom-claim": "value",
  "iss": "your-app",
  "iat": 1640995200,
  "exp": 1641081600
}
```

### Token Operations

```java
@Service
public class TokenService {

    @Autowired
    private JwtService jwtService;

    public TokenPair generateTokens(LazyUser user) {
        return jwtService.createTokens(user);
    }

    public TokenPair generateTokensWithClaims(LazyUser user, Map<String, Object> extraClaims) {
        return jwtService.createTokens(user, extraClaims);
    }

    public TokenPair refreshTokens(String refreshToken) {
        return jwtService.refresh(refreshToken);
    }

    public LazyUser validateToken(String token) {
        return jwtService.validateToken(token);
    }

    public void revokeToken(String token) {
        jwtService.revokeToken(token);
    }

    public boolean isTokenValid(String token) {
        return jwtService.isValid(token);
    }
}
```

### Token Blacklisting

```java
@Service
public class LogoutService {

    @Autowired
    private TokenBlacklist tokenBlacklist;

    @PostMapping("/logout")
    @Secured
    public void logout(HttpServletRequest request) {
        String token = extractTokenFromRequest(request);
        
        // Add token to blacklist
        tokenBlacklist.blacklist(token);
        
        // Optionally, blacklist refresh token as well
        String refreshToken = extractRefreshToken(request);
        if (refreshToken != null) {
            tokenBlacklist.blacklist(refreshToken);
        }
    }

    @PostMapping("/logout-all")
    @Secured
    public void logoutAllDevices() {
        LazyUser user = Auth.user();
        
        // Blacklist all tokens for current user
        tokenBlacklist.blacklistAllForUser(user.getId());
    }
}
```

## Advanced Features

### SpEL Expressions

LazySpringSecurity supports Spring Expression Language (SpEL) for complex authorization conditions:

#### Available Variables
- `principal` - Current LazyUser object
- `#parameterName` - Method parameters by name
- `authentication` - Spring Security Authentication object
- `request` - Current HttpServletRequest (in web context)

#### Examples

**Parameter-based Authorization:**
```java
@Secured(condition = "#userId == principal.id")
@GetMapping("/users/{userId}/orders")
public List<Order> getUserOrders(@PathVariable String userId) {
    return orderService.findByUserId(userId);
}
```

**Request Body Validation:**
```java
@Secured(condition = "#order.customerId == principal.id or hasRole('ADMIN')")
@PostMapping("/orders")
public Order createOrder(@RequestBody Order order) {
    return orderService.create(order);
}
```

**Time-based Authorization:**
```java
@Secured(condition = "hasRole('ADMIN') or T(java.time.LocalTime).now().getHour() < 18")
@GetMapping("/business-hours-data")
public Data getBusinessHoursData() {
    return dataService.getBusinessData();
}
```

**Complex Business Logic:**
```java
@Secured(condition = """
    hasRole('MANAGER') and 
    #report.department == principal.getClaim('department') and
    #report.confidentialityLevel <= principal.getClaim('clearanceLevel')
""")
@GetMapping("/reports/{reportId}")
public Report getReport(@PathVariable Long reportId, @RequestParam Report report) {
    return reportService.findById(reportId);
}
```

### Custom User Details

Extend LazyUser with custom claims:

```java
public class CustomUserService {

    public TokenPair authenticateUser(String username, String password) {
        User user = userRepository.findByUsername(username);
        
        if (user != null && passwordEncoder.matches(password, user.getPassword())) {
            LazyUser lazyUser = LazyUser.builder()
                .id(user.getId())
                .username(user.getUsername())
                .roles(user.getRoles())
                .permissions(user.getPermissions())
                // Custom claims
                .claim("email", user.getEmail())
                .claim("department", user.getDepartment())
                .claim("clearanceLevel", user.getClearanceLevel())
                .claim("lastLogin", user.getLastLogin())
                .claim("preferences", user.getPreferences())
                .build();

            return jwtService.createTokens(lazyUser);
        }

        throw new UnauthorizedException("Invalid credentials");
    }
}
```

Access custom claims:

```java
@RestController
public class UserController {

    @Secured
    @GetMapping("/dashboard")
    public DashboardData getDashboard(LazyUser user) {
        String department = user.getClaim("department");
        Integer clearanceLevel = user.getClaim("clearanceLevel", Integer.class);
        LocalDateTime lastLogin = user.getClaim("lastLogin", LocalDateTime.class);

        return dashboardService.getDashboardData(department, clearanceLevel, lastLogin);
    }
}
```

### Rate Limiting Configuration

```java
@Configuration
public class RateLimitConfig {

    @Bean
    public RateLimitManager rateLimitManager() {
        return RateLimitManager.builder()
            .defaultWindow(Duration.ofMinutes(1))
            .defaultRequests(100)
            .keyResolver(request -> {
                // Custom key resolution logic
                LazyUser user = LazySecurityContext.getCurrentUser();
                return user.isAuthenticated() ? user.getId() : request.getRemoteAddr();
            })
            .storage(redisTemplate()) // Use Redis for distributed rate limiting
            .build();
    }
}
```

### Audit Configuration

```java
@Configuration
public class AuditConfig {

    @Bean
    public AuditEventHandler auditEventHandler() {
        return new CustomAuditEventHandler();
    }
    
    public class CustomAuditEventHandler implements AuditEventHandler {
        
        @Override
        public void handle(AuditEvent event) {
            // Custom audit handling logic
            if (event.getLevel() == AuditLevel.CRITICAL) {
                alertingService.sendSecurityAlert(event);
            }
            
            auditRepository.save(event);
            elasticsearchService.index(event);
        }
    }
}
```

## Best Practices

### Security Configuration

1. **Environment-based Secrets**
   ```bash
   # Never hardcode secrets in source code
   export JWT_SECRET=$(openssl rand -base64 32)
   export DB_PASSWORD=secure-password
   ```

2. **Token Expiration Strategy**
   ```yaml
   lazy-security:
     jwt:
       expiration: 15m      # Short-lived access tokens
       refresh-expiration: 7d # Longer-lived refresh tokens
   ```

3. **CORS Configuration**
   ```yaml
   lazy-security:
     cors:
       allowed-origins:
         - https://yourdomain.com    # Specific domains only
         - https://app.yourdomain.com
       allow-credentials: true
   ```

### Authorization Design

1. **Role Hierarchy**
   ```java
   // Use hierarchical roles
   public enum Role {
       USER,
       MODERATOR,
       ADMIN,
       SUPER_ADMIN
   }
   
   // SUPER_ADMIN inherits all permissions from ADMIN, etc.
   ```

2. **Permission Granularity**
   ```java
   // Use specific permissions for fine-grained control
   @Secured(permissions = {"users:read", "users:write"})
   @Secured(permissions = "posts:delete")
   @Secured(permissions = "admin:system_settings")
   ```

3. **Progressive Security**
   ```java
   @RestController
   public class UserController {
   
       @Public // Start with public access
       @GetMapping("/users")
       public List<User> getUsers() { }
   
       @Secured // Add authentication requirement
       @GetMapping("/users/me")
       public User getCurrentUser() { }
   
       @Secured("ADMIN") // Add role requirement
       @PostMapping("/users")
       public User createUser() { }
   
       @Secured(condition = "#id == principal.id or hasRole('ADMIN')") // Add complex logic
       @PutMapping("/users/{id}")
       public User updateUser(@PathVariable String id) { }
   }
   ```

### Performance Optimization

1. **Annotation Caching**
   ```java
   // Annotations are automatically cached, but you can optimize SpEL expressions
   @Secured(condition = "principal.getClaim('department') == 'IT'") // Cached
   @Secured(condition = "hasRole('ADMIN')") // Use simple expressions when possible
   ```

2. **JWT Validation**
   ```yaml
   lazy-security:
     jwt:
       # Use appropriate algorithms
       algorithm: HS256  # Fast for symmetric keys
       # algorithm: RS256 # Use for asymmetric keys in microservices
   ```

3. **Database Optimization**
   ```java
   // Optimize user and role queries
   @Entity
   public class User {
       @ManyToMany(fetch = FetchType.EAGER) // For small role sets
       private Set<Role> roles;
       
       @ElementCollection(fetch = FetchType.EAGER) // For simple permissions
       private Set<String> permissions;
   }
   ```

### Error Handling

1. **Custom Error Messages**
   ```java
   @Secured(
       value = "ADMIN", 
       message = "Administrator privileges required for user management operations"
   )
   @DeleteMapping("/users/{id}")
   public void deleteUser(@PathVariable Long id) { }
   ```

2. **Global Exception Handling**
   ```java
   @RestControllerAdvice
   public class SecurityExceptionHandler {
   
       @ExceptionHandler(UnauthorizedException.class)
       public ResponseEntity<ErrorResponse> handleUnauthorized(UnauthorizedException ex) {
           return ResponseEntity.status(401)
               .body(new ErrorResponse("UNAUTHORIZED", ex.getMessage()));
       }
       
       @ExceptionHandler(AccessDeniedException.class)
       public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException ex) {
           // Log security violation
           securityLogger.logAccessDenied(Auth.user(), ex);
           
           return ResponseEntity.status(403)
               .body(new ErrorResponse("ACCESS_DENIED", "Insufficient privileges"));
       }
   }
   ```

### Testing

1. **Unit Testing with Security**
   ```java
   @ExtendWith(MockitoExtension.class)
   class UserServiceTest {
   
       @Test
       void testSecureMethod() {
           // Mock security context
           LazyUser mockUser = LazyUser.builder()
               .id("123")
               .username("testuser")
               .roles("USER")
               .build();
               
           LazySecurityContext.setCurrentUser(mockUser);
           
           try {
               // Test your secured methods
               userService.updateProfile(request);
           } finally {
               LazySecurityContext.clear();
           }
       }
   }
   ```

2. **Integration Testing**
   ```java
   @SpringBootTest
   @AutoConfigureMockMvc
   class SecurityIntegrationTest {
   
       @Autowired
       private MockMvc mockMvc;
       
       @Autowired
       private JwtService jwtService;
   
       @Test
       void testSecuredEndpoint() throws Exception {
           LazyUser user = LazyUser.builder()
               .id("123")
               .username("testuser")
               .roles("ADMIN")
               .build();
               
           String token = jwtService.createTokens(user).accessToken();
   
           mockMvc.perform(get("/api/admin/users")
                   .header("Authorization", "Bearer " + token))
               .andExpect(status().isOk());
       }
   }
   ```

## Troubleshooting

### Common Issues

#### 1. JWT Secret Too Short
**Error:** `JWT secret must be at least 256 bits`
**Solution:**
```properties
# Ensure secret is at least 32 characters
lazy-security.jwt.secret=your-very-secure-256-bit-secret-key-here-change-this-in-production
```

#### 2. Token Not Found
**Error:** `401 Unauthorized` even with valid token
**Solution:**
```java
// Verify token format in requests
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

#### 3. CORS Issues
**Error:** Browser blocks requests due to CORS
**Solution:**
```yaml
lazy-security:
  cors:
    enabled: true
    allowed-origins:
      - http://localhost:3000  # Add your frontend URL
    allowed-methods:
      - GET
      - POST
      - PUT
      - DELETE
      - OPTIONS
```

#### 4. SpEL Expression Errors
**Error:** `Expression parsing failed`
**Solution:**
```java
// Check expression syntax
@Secured(condition = "#userId == principal.id") // Correct
@Secured(condition = "#userId = principal.id")  // Incorrect (single =)
```

#### 5. Role Not Working
**Error:** `403 Forbidden` even with correct role
**Solution:**
```java
// Verify role format (case-sensitive)
@Secured("ADMIN")      // Correct
@Secured("admin")      // May not match if roles are uppercase

// Check user role assignment
LazyUser user = LazyUser.builder()
    .roles("USER", "ADMIN") // Ensure ADMIN role is included
    .build();
```

### Debug Mode

Enable debug mode to see configuration details:

```yaml
lazy-security:
  debug: true
  
logging:
  level:
    ao.sudojed.lss: DEBUG
```

### Health Checks

Monitor security status:

```java
@RestController
public class SecurityHealthController {

    @Public
    @GetMapping("/health/security")
    public Map<String, Object> securityHealth() {
        return Map.of(
            "jwtEnabled", jwtService.isEnabled(),
            "tokenBlacklistSize", tokenBlacklist.size(),
            "activeUsers", LazySecurityContext.getActiveUserCount()
        );
    }
}
```

## Migration Guide

### From Spring Security

If you're migrating from traditional Spring Security:

**Before (Spring Security):**
```java
@Configuration
@EnableWebSecurity
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
                .anyRequest().authenticated())
            .build();
    }
}

@RestController
public class UserController {

    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) { }
}
```

**After (LazySpringSecurity):**
```java
@SpringBootApplication
@EnableLazySecurity
public class Application { }

@RestController
public class UserController {

    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) { }
}
```

### From Other JWT Libraries

**Before (Manual JWT):**
```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    // 50+ lines of boilerplate code for token extraction and validation
}

@RestController
public class AuthController {
    // Manual token generation and user authentication
    // 100+ lines of authentication logic
}
```

**After (LazySpringSecurity):**
```java
@RestController
public class AuthController {

    @Login(userService = UserService.class)
    @PostMapping("/login")
    public TokenResponse login(@RequestBody LoginRequest request) {
        // Automatic implementation
    }

    @Register(userService = UserService.class)
    @PostMapping("/register")
    public UserResponse register(@RequestBody RegisterRequest request) {
        // Automatic implementation
    }
}
```

### Configuration Migration

**application.yml migration:**
```yaml
# Old Spring Security configuration
spring:
  security:
    user:
      name: admin
      password: secret
      roles: ADMIN

# New LazySpringSecurity configuration  
lazy-security:
  jwt:
    secret: ${JWT_SECRET}
    expiration: 24h
  cors:
    enabled: true
    allowed-origins:
      - http://localhost:3000
```

---

**Version**: 1.0.0-SNAPSHOT  
**Last Updated**: January 2026  
**Spring Boot Compatibility**: 3.4.x  
**Java Requirement**: 21+

For more information, visit our [GitHub repository](https://github.com/sudojed/lazy-spring-security).