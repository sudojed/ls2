package ao.sudojed.lss.util;

import java.util.function.Supplier;

import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.core.LazyUser;

/**
 * LazySpringSecurity utility class.
 * Convenient methods for security checks in code.
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * // Check authentication
 * if (LazyAuth.isAuthenticated()) {
 *     // user is logged in
 * }
 * 
 * // Check roles
 * if (LazyAuth.hasRole("ADMIN")) {
 *     // is admin
 * }
 * 
 * // Execute code conditionally
 * LazyAuth.ifRole("ADMIN", () -> {
 *     // only executes if admin
 * });
 * 
 * // Get current user
 * LazyUser user = LazyAuth.user();
 * }</pre>
 *
 * @author Sudojed Team
 */
public final class LazyAuth {

    private LazyAuth() {
        // Utility class
    }

    /**
     * Gets the current user.
     */
    public static LazyUser user() {
        return LazySecurityContext.getCurrentUser();
    }

    /**
     * Gets the current user's ID.
     */
    public static String userId() {
        return LazySecurityContext.getUserId();
    }

    /**
     * Gets the current user's username.
     */
    public static String username() {
        return LazySecurityContext.getUsername();
    }

    /**
     * Checks if authenticated.
     */
    public static boolean isAuthenticated() {
        return LazySecurityContext.isAuthenticated();
    }

    /**
     * Checks if anonymous.
     */
    public static boolean isAnonymous() {
        return !isAuthenticated();
    }

    /**
     * Checks if has role.
     */
    public static boolean hasRole(String role) {
        return LazySecurityContext.hasRole(role);
    }

    /**
     * Checks if has any of the roles.
     */
    public static boolean hasAnyRole(String... roles) {
        return LazySecurityContext.hasAnyRole(roles);
    }

    /**
     * Checks if has all the roles.
     */
    public static boolean hasAllRoles(String... roles) {
        return LazySecurityContext.hasAllRoles(roles);
    }

    /**
     * Checks if has permission.
     */
    public static boolean hasPermission(String permission) {
        return LazySecurityContext.hasPermission(permission);
    }

    /**
     * Checks if is admin.
     */
    public static boolean isAdmin() {
        return LazySecurityContext.isAdmin();
    }

    /**
     * Executes action if authenticated.
     */
    public static void ifAuthenticated(Runnable action) {
        if (isAuthenticated()) {
            action.run();
        }
    }

    /**
     * Executes action if has role.
     */
    public static void ifRole(String role, Runnable action) {
        if (hasRole(role)) {
            action.run();
        }
    }

    /**
     * Executes action if admin.
     */
    public static void ifAdmin(Runnable action) {
        if (isAdmin()) {
            action.run();
        }
    }

    /**
     * Returns value if authenticated, else default value.
     */
    public static <T> T ifAuthenticated(Supplier<T> supplier, T defaultValue) {
        return isAuthenticated() ? supplier.get() : defaultValue;
    }

    /**
     * Returns value if has role, else default value.
     */
    public static <T> T ifRole(String role, Supplier<T> supplier, T defaultValue) {
        return hasRole(role) ? supplier.get() : defaultValue;
    }

    /**
     * Checks if the current user is the resource owner.
     */
    public static boolean isOwner(String resourceOwnerId) {
        return userId().equals(resourceOwnerId);
    }

    /**
     * Checks if is admin or resource owner.
     */
    public static boolean isAdminOrOwner(String resourceOwnerId) {
        return isAdmin() || isOwner(resourceOwnerId);
    }
}
