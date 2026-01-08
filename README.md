# LazySpringSecurity (LSS)

**Zero-configuration security for Spring Boot APIs**

[![JitPack](https://jitpack.io/v/jedin01/ls2.svg)](https://jitpack.io/#jedin01/ls2)

Transform complex Spring Security configurations into simple, readable annotations. LSS eliminates boilerplate code and makes API security intuitive for developers of all levels.

## Why LSS?

**Traditional Spring Security:**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> authz
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated()
        )
        .oauth2ResourceServer(oauth2 -> oauth2
            .jwt(jwt -> jwt.decoder(jwtDecoder()))
        );
        return http.build();
    }
    // ... 50+ more lines of configuration
}
```

**With LazySpringSecurity:**
```java
@RestController
public class ApiController {
    
    @PublicAccess
    @GetMapping("/api/public/data")
    public Data getPublicData() { }
    
    @Secured("ADMIN")
    @DeleteMapping("/api/admin/users/{id}")
    public void deleteUser(@PathVariable Long id) { }
    
    @Owner(field = "userId")
    @GetMapping("/api/users/{userId}/profile")
    public Profile getProfile(@PathVariable Long userId) { }
}
```

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

### 2. Configure (application.yml)

```yaml
lss:
  jwt:
    secret: "your-256-bit-secret-key"
    expiration: 86400000  # 24 hours
  security:
    enabled: true
    cors:
      allowed-origins: ["http://localhost:3000"]
```

### 3. Secure Your APIs

```java
@RestController
public class MyController {
    
    // Public endpoint
    @Public
    @GetMapping("/health")
    public String health() {
        return "OK";
    }
    
    // Requires authentication
    @Secured
    @GetMapping("/profile")
    public User getProfile(Principal principal) {
        return userService.findByUsername(principal.getName());
    }
    
    // Admin only
    @Secured("ADMIN")
    @DeleteMapping("/users/{id}")
    public void deleteUser(@PathVariable Long id) {
        userService.delete(id);
    }
    
    // Multiple roles
    @Secured({"ADMIN", "MODERATOR"})
    @PostMapping("/moderate")
    public void moderateContent(@RequestBody Content content) {
        contentService.moderate(content);
    }
    
    // Owner verification
    @Owner(field = "userId")
    @GetMapping("/users/{userId}/settings")
    public Settings getUserSettings(@PathVariable Long userId) {
        return settingsService.findByUserId(userId);
    }
    
    // Rate limiting
    @RateLimit(requests = 100, window = 60)
    @PostMapping("/process")
    public Result processData(@RequestBody DataRequest request) {
        return dataService.process(request);
    }
    
    // Audit logging
    @Audit(action = "USER_DELETION", level = Audit.AuditLevel.CRITICAL)
    @Secured("ADMIN")
    @DeleteMapping("/admin/users/{id}")
    public void adminDeleteUser(@PathVariable Long id) {
        userService.adminDelete(id);
    }
}
```

## Key Features

### 🛡️ **Security Annotations**
- `@Public` - No authentication required
- `@Secured` - Role-based access control with advanced conditions
- `@Owner` - Resource ownership verification
- `@RateLimit` - Request rate limiting
- `@Audit` - Automatic security event logging

### ⚡ **Performance**
- `@Cached` - Security-aware intelligent caching
- Built-in rate limiting and DDoS protection
- Optimized JWT processing

### 🔧 **Developer Experience**
- Zero Spring Security configuration required
- Auto-configuration for JWT, CORS, CSRF
- IntelliJ IDEA and VS Code support
- Comprehensive error messages

### 🚀 **Production Ready**
- Battle-tested security patterns
- Extensive audit logging
- Performance monitoring hooks
- Configurable security policies

## Advanced Usage

### Dynamic Authorization
```java
@Secured(condition = "#userId == principal.id or hasRole('ADMIN')")
@PutMapping("/users/{userId}")
public User updateUser(@PathVariable Long userId, @RequestBody User user) {
    return userService.update(userId, user);
}
```

### Permission-Based Access
```java
@Secured(permissions = {"users:read", "users:write"})
@PostMapping("/users")
public User createUser(@RequestBody CreateUserRequest request) {
    return userService.create(request);
}
```

### Automated Login Endpoints
```java
@Login(
    userService = UserService.class,
    findMethod = "findByEmail"
)
@PostMapping("/auth/login")
public ResponseEntity<?> login(@RequestBody LoginRequest request) {
    // Implementation generated automatically
}
```

## Enterprise Features

- **Multi-tenant support** - Isolated security contexts
- **Integration APIs** - LDAP, OAuth2, SAML
- **Compliance** - Built-in GDPR, SOX, HIPAA patterns
- **Monitoring** - Metrics and security dashboards
- **Performance** - Sub-millisecond authorization decisions

## Documentation

- [📖 Complete Annotation Guide](ANNOTATIONS_GUIDE.md)
- [🚀 JitPack Setup Guide](JITPACK_USAGE.md)
- [💡 Working Examples](example-project/)

## Community

- **Issues**: [GitHub Issues](https://github.com/jedin01/ls2/issues)
- **Discussions**: [GitHub Discussions](https://github.com/jedin01/ls2/discussions)
- **Email**: abner@sudojed.ao

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

**Transform your Spring Boot security from complex to simple. Get started with LSS today.** 🛡️