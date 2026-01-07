package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.Secured;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.demo.service.UserService;
import ao.sudojed.lss.facade.Auth;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * User profile controller.
 *
 * Demonstrates two ways to access the user:
 *
 * 1. Via LazyUser parameter (automatic injection):
 *    public Map<String, Object> getProfile(LazyUser user) { ... }
 *
 * 2. Via Auth facade (static access):
 *    Auth.user()     // gets user
 *    Auth.id()       // gets ID
 *    Auth.hasRole()  // checks role
 *
 * @author Sudojed Team
 */
@RestController
@RequestMapping("/api")
public class ProfileController {

    private final UserService userService;

    public ProfileController(UserService userService) {
        this.userService = userService;
    }

    /**
     * Returns the logged user's profile.
     *
     * Example using LazyUser parameter (traditional way)
     *
     * Usage: GET /api/profile
     * Header: Authorization: Bearer <token>
     */
    @Secured
    @GetMapping("/profile")
    public Map<String, Object> getProfile(LazyUser user) {
        return Map.of(
            "id",
            user.getId(),
            "username",
            user.getUsername(),
            "email",
            user.getClaim("email", ""),
            "roles",
            user.getRoles(),
            "isAdmin",
            user.isAdmin(),
            "claims",
            user.getClaims()
        );
    }

    /**
     * Returns current user information using Auth facade.
     *
     * Example using Auth facade (static access):
     * - Auth.user()    gets current user
     * - Auth.id()      gets user ID
     * - Auth.isAdmin() checks admin status
     *
     * Usage: GET /api/me
     * Header: Authorization: Bearer <token>
     */
    @Secured
    @GetMapping("/me")
    public Map<String, Object> me() {
        // Uses Auth facade - no parameter needed!
        return Map.of(
            "id",
            Auth.id(),
            "username",
            Auth.username(),
            "email",
            Auth.claim("email"),
            "roles",
            Auth.user().getRoles(),
            "isAdmin",
            Auth.isAdmin(),
            "isGuest",
            Auth.guest()
        );
    }

    /**
     * Updates user profile.
     *
     * Usage: PUT /api/profile
     * Body: { "displayName": "John Doe", "email": "newemail@example.com" }
     */
    @Secured
    @PutMapping("/profile")
    public ResponseEntity<Map<String, Object>> updateProfile(
        @RequestBody Map<String, String> updates
    ) {
        // Uses Auth.id() to get current user ID
        User dbUser = userService.findById(Auth.id()).orElse(null);

        if (dbUser == null) {
            return ResponseEntity.notFound().build();
        }

        // Updates fields
        if (updates.containsKey("displayName")) {
            dbUser.setDisplayName(updates.get("displayName"));
        }
        if (updates.containsKey("email")) {
            dbUser.setEmail(updates.get("email"));
        }

        userService.save(dbUser);

        return ResponseEntity.ok(
            Map.of(
                "message",
                "Profile updated successfully!",
                "user",
                Map.of(
                    "id",
                    dbUser.getId(),
                    "username",
                    dbUser.getUsername(),
                    "displayName",
                    dbUser.getDisplayName(),
                    "email",
                    dbUser.getEmail()
                )
            )
        );
    }
}
