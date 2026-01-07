package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Secured;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import ao.sudojed.lss.facade.Auth;
import ao.sudojed.lss.facade.Guard;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Administrative controller demonstrating Auth and Guard facades.
 *
 * Two ways to protect endpoints:
 * 1. Declarative: @Secured("ADMIN"), @Secured (automatic verification via AOP)
 * 2. Imperative: Guard.admin(), Guard.role() (manual verification in code)
 *
 * @author Sudojed Team
 */
@RestController
@RequestMapping("/api/admin")
public class AdminController {

    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Lists all system users.
     *
     * Uses @Secured("ADMIN") for declarative verification.
     * Uses Auth.username() to get logged admin data.
     */
    @Secured("ADMIN")
    @GetMapping("/users")
    public Map<String, Object> listUsers() {
        // No LazyUser parameter - uses Auth facade!
        List<Map<String, Object>> users = userService
            .findAll()
            .stream()
            .map(user ->
                Map.<String, Object>of(
                    "id",
                    user.getId(),
                    "username",
                    user.getUsername(),
                    "email",
                    user.getEmail(),
                    "roles",
                    user.getRoles(),
                    "createdAt",
                    user.getCreatedAt().toString()
                )
            )
            .toList();

        return Map.of(
            "total",
            users.size(),
            "users",
            users,
            "requestedBy",
            Auth.username() // Auth facade!
        );
    }

    /**
     * Gets details of a specific user.
     *
     * Uses Guard.admin() for imperative verification.
     * This allows conditional logic before the verification.
     */
    @GetMapping("/users/{userId}")
    public ResponseEntity<Map<String, Object>> getUser(
        @PathVariable String userId
    ) {
        // Imperative verification
        Guard.admin();

        return userService
            .findById(userId)
            .map(user ->
                ResponseEntity.ok(
                    Map.<String, Object>of(
                        "id",
                        user.getId(),
                        "username",
                        user.getUsername(),
                        "email",
                        user.getEmail(),
                        "displayName",
                        user.getDisplayName(),
                        "roles",
                        user.getRoles(),
                        "createdAt",
                        user.getCreatedAt().toString()
                    )
                )
            )
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Deletes a user.
     *
     * Demonstrates combined usage of Guard and Auth:
     * - Guard.admin() to authorize
     * - Auth.id() to check self-deletion
     */
    @DeleteMapping("/users/{userId}")
    public ResponseEntity<Map<String, Object>> deleteUser(
        @PathVariable String userId
    ) {
        // Imperative verification
        Guard.admin();

        // Does not allow self-deletion - uses Auth.id()!
        if (userId.equals(Auth.id())) {
            return ResponseEntity.badRequest().body(
                Map.of(
                    "error",
                    "CANNOT_DELETE_SELF",
                    "message",
                    "You cannot delete your own account"
                )
            );
        }

        boolean deleted = userService.deleteById(userId);

        if (deleted) {
            return ResponseEntity.ok(
                Map.of(
                    "message",
                    "User deleted successfully",
                    "deletedUserId",
                    userId,
                    "deletedBy",
                    Auth.username() // Auth facade!
                )
            );
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * Adds role to a user.
     *
     * Uses Guard.role() to require specific role.
     */
    @PostMapping("/users/{userId}/roles")
    public ResponseEntity<Map<String, Object>> addRole(
        @PathVariable String userId,
        @RequestBody Map<String, String> body
    ) {
        // Requires ADMIN role
        Guard.role("ADMIN");

        String role = body.get("role");
        if (role == null || role.isBlank()) {
            return ResponseEntity.badRequest().body(
                Map.of(
                    "error",
                    "MISSING_ROLE",
                    "message",
                    "Field 'role' is required"
                )
            );
        }

        return userService
            .findById(userId)
            .map(user -> {
                user.addRole(role);
                userService.save(user);
                return ResponseEntity.ok(
                    Map.<String, Object>of(
                        "message",
                        "Role added successfully",
                        "userId",
                        userId,
                        "roles",
                        user.getRoles()
                    )
                );
            })
            .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Administrative dashboard with statistics.
     *
     * Demonstrates fluent verification with Guard.check()
     */
    @GetMapping("/dashboard")
    public Map<String, Object> dashboard() {
        // Fluent verification - allows combining conditions
        Guard.check().role("ADMIN").authorize();

        List<User> allUsers = userService.findAll();

        long totalUsers = allUsers.size();
        long adminCount = allUsers
            .stream()
            .filter(u -> u.getRoles().contains("ADMIN"))
            .count();

        return Map.of(
            "stats",
            Map.of(
                "totalUsers",
                totalUsers,
                "adminUsers",
                adminCount,
                "regularUsers",
                totalUsers - adminCount
            ),
            "admin",
            Map.of(
                "username",
                Auth.username(),
                "roles",
                Auth.user().getRoles(),
                "isAdmin",
                Auth.isAdmin()
            ),
            "message",
            "Welcome to the admin panel!"
        );
    }

    /**
     * Endpoint that accepts ADMIN or MANAGER.
     *
     * Demonstrates Guard.anyRole() for multiple accepted roles.
     */
    @GetMapping("/reports")
    public Map<String, Object> reports() {
        // Accepts ADMIN or MANAGER
        Guard.anyRole("ADMIN", "MANAGER");

        return Map.of(
            "reports",
            List.of(
                Map.of("name", "Monthly Sales", "value", 15000),
                Map.of("name", "New Users", "value", 42),
                Map.of("name", "Pending Orders", "value", 7)
            ),
            "generatedBy",
            Auth.username(),
            "userRoles",
            Auth.user().getRoles()
        );
    }
}
