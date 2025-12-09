package ao.sudojed.lss.core;

import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Simplified security context for LazySpringSecurity.
 * Provides easy access to current user without boilerplate.
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * // Gets current user (never null)
 * LazyUser user = LazySecurityContext.getCurrentUser();
 * 
 * // Checks if authenticated
 * if (LazySecurityContext.isAuthenticated()) {
 *     // ...
 * }
 * 
 * // Gets user ID directly
 * String userId = LazySecurityContext.getUserId();
 * 
 * // Checks role
 * if (LazySecurityContext.hasRole("ADMIN")) {
 *     // ...
 * }
 * }</pre>
 *
 * @author Sudojed Team
 */
public final class LazySecurityContext {

    private static final ThreadLocal<LazyUser> userHolder = new ThreadLocal<>();

    private LazySecurityContext() {
        // Utility class
    }

    /**
     * Gets the current authenticated user.
     * Returns anonymous user if not authenticated.
     */
    public static LazyUser getCurrentUser() {
        LazyUser cachedUser = userHolder.get();
        if (cachedUser != null) {
            return cachedUser;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !authentication.isAuthenticated()) {
            return LazyUser.anonymous();
        }

        Object principal = authentication.getPrincipal();
        
        if (principal instanceof LazyUser) {
            return (LazyUser) principal;
        }

        // Fallback for other principal types
        return LazyUser.builder()
                .id(authentication.getName())
                .username(authentication.getName())
                .authenticated(authentication.isAuthenticated())
                .roles(authentication.getAuthorities().stream()
                        .map(a -> a.getAuthority().replace("ROLE_", ""))
                        .toList())
                .build();
    }

    /**
     * Gets current user as Optional.
     * Empty if not authenticated.
     */
    public static Optional<LazyUser> getUser() {
        LazyUser user = getCurrentUser();
        return user.isAuthenticated() ? Optional.of(user) : Optional.empty();
    }

    /**
     * Checks if there is an authenticated user.
     */
    public static boolean isAuthenticated() {
        return getCurrentUser().isAuthenticated();
    }

    /**
     * Gets the current user's ID.
     */
    public static String getUserId() {
        return getCurrentUser().getId();
    }

    /**
     * Gets the current user's username.
     */
    public static String getUsername() {
        return getCurrentUser().getUsername();
    }

    /**
     * Checks if the user has a specific role.
     */
    public static boolean hasRole(String role) {
        return getCurrentUser().hasRole(role);
    }

    /**
     * Checks if the user has any of the roles.
     */
    public static boolean hasAnyRole(String... roles) {
        return getCurrentUser().hasAnyRole(roles);
    }

    /**
     * Checks if the user has all the roles.
     */
    public static boolean hasAllRoles(String... roles) {
        return getCurrentUser().hasAllRoles(roles);
    }

    /**
     * Checks if the user has a specific permission.
     */
    public static boolean hasPermission(String permission) {
        return getCurrentUser().hasPermission(permission);
    }

    /**
     * Checks if the user is admin.
     */
    public static boolean isAdmin() {
        return getCurrentUser().isAdmin();
    }

    /**
     * Sets the user in context (internal use).
     */
    public static void setCurrentUser(LazyUser user) {
        userHolder.set(user);
    }

    /**
     * Clears the user context (internal use).
     */
    public static void clear() {
        userHolder.remove();
    }

    /**
     * Executes an action as a specific user (useful for tests).
     */
    public static <T> T runAs(LazyUser user, java.util.function.Supplier<T> action) {
        LazyUser previous = userHolder.get();
        try {
            setCurrentUser(user);
            return action.get();
        } finally {
            if (previous != null) {
                setCurrentUser(previous);
            } else {
                clear();
            }
        }
    }

    /**
     * Executes an action as a specific user (no return).
     */
    public static void runAs(LazyUser user, Runnable action) {
        runAs(user, () -> {
            action.run();
            return null;
        });
    }
}
