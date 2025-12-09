package ao.sudojed.lss.facade;

import ao.sudojed.lss.exception.AccessDeniedException;

/**
 * Utility class for authorization verification.
 * Provides static methods for declarative permission checking.
 * 
 * <h2>Usage</h2>
 * <pre>{@code
 * // Check role
 * Guard.role("ADMIN");  // throws exception if not admin
 * 
 * // Check any role
 * Guard.anyRole("ADMIN", "MANAGER");
 * 
 * // Check if owner of resource
 * Guard.owner(resourceOwnerId);
 * 
 * // Check custom condition
 * Guard.when(user.isActive(), "User is inactive");
 * }</pre>
 * 
 * @author Sudojed Team
 */
public final class Guard {

    private Guard() {
        // Utility class
    }

    // ========================================================================
    // ROLE CHECKS
    // ========================================================================

    /**
     * Requires the user to have the specified role.
     * 
     * @param role required role
     * @throws AccessDeniedException if doesn't have the role
     */
    public static void role(String role) {
        Auth.requireAuth();
        if (!Auth.hasRole(role)) {
            throw new AccessDeniedException("Access denied. Required role: " + role);
        }
    }

    /**
     * Requires the user to have at least one of the roles.
     * 
     * @param roles accepted roles
     * @throws AccessDeniedException if doesn't have any
     */
    public static void anyRole(String... roles) {
        Auth.requireAuth();
        if (!Auth.hasAnyRole(roles)) {
            throw new AccessDeniedException(
                "Access denied. Requires one of: " + String.join(", ", roles));
        }
    }

    /**
     * Requires the user to have all the specified roles.
     * 
     * @param roles required roles
     * @throws AccessDeniedException if doesn't have all
     */
    public static void allRoles(String... roles) {
        Auth.requireAuth();
        if (!Auth.hasAllRoles(roles)) {
            throw new AccessDeniedException(
                "Access denied. Requires all roles: " + String.join(", ", roles));
        }
    }

    /**
     * Requires the user to be an admin.
     * 
     * @throws AccessDeniedException if not admin
     */
    public static void admin() {
        role("ADMIN");
    }

    // ========================================================================
    // OWNERSHIP CHECKS
    // ========================================================================

    /**
     * Checks if the current user is the owner of the resource.
     * Admin has automatic bypass.
     * 
     * @param resourceOwnerId resource owner ID
     * @throws AccessDeniedException if not owner nor admin
     */
    public static void owner(String resourceOwnerId) {
        Auth.requireAuth();
        
        String currentUserId = Auth.id();
        
        // Admin can access any resource
        if (Auth.isAdmin()) {
            return;
        }
        
        if (!currentUserId.equals(resourceOwnerId)) {
            throw new AccessDeniedException(
                "Access denied. You are not the owner of this resource.");
        }
    }

    /**
     * Checks if the current user is the owner OR has a specific role.
     * 
     * @param resourceOwnerId resource owner ID
     * @param bypassRole role that allows bypass
     * @throws AccessDeniedException if not owner nor has the role
     */
    public static void ownerOr(String resourceOwnerId, String bypassRole) {
        Auth.requireAuth();
        
        if (Auth.hasRole(bypassRole)) {
            return;
        }
        
        if (!Auth.id().equals(resourceOwnerId)) {
            throw new AccessDeniedException(
                "Access denied. Requires ownership or role: " + bypassRole);
        }
    }

    // ========================================================================
    // CONDITIONAL CHECKS
    // ========================================================================

    /**
     * Requires a condition to be true.
     * 
     * @param condition condition to verify
     * @param message error message if fails
     * @throws AccessDeniedException if condition is false
     */
    public static void when(boolean condition, String message) {
        if (!condition) {
            throw new AccessDeniedException(message);
        }
    }

    /**
     * Requires a condition to be true.
     * 
     * @param condition condition to verify
     * @throws AccessDeniedException if condition is false
     */
    public static void when(boolean condition) {
        when(condition, "Access denied");
    }

    /**
     * Requires authentication.
     * 
     * @throws ao.sudojed.lss.exception.UnauthorizedException if not authenticated
     */
    public static void authenticated() {
        Auth.requireAuth();
    }

    /**
     * Allows only guests (not authenticated).
     * Useful for login/register pages.
     * 
     * @throws AccessDeniedException if already authenticated
     */
    public static void guest() {
        if (Auth.check()) {
            throw new AccessDeniedException("Action available only for guests");
        }
    }

    // ========================================================================
    // FLUENT CHECKS
    // ========================================================================

    /**
     * Starts a fluent verification.
     * 
     * @return builder for fluent verification
     */
    public static GuardChain check() {
        return new GuardChain();
    }

    /**
     * Builder for fluent verifications.
     */
    public static class GuardChain {
        private boolean passed = true;
        private String failMessage = "Access denied";

        /**
         * Adds role verification.
         */
        public GuardChain role(String role) {
            if (passed && !Auth.hasRole(role)) {
                passed = false;
                failMessage = "Required role: " + role;
            }
            return this;
        }

        /**
         * Adds ownership verification.
         */
        public GuardChain owner(String resourceOwnerId) {
            if (passed && !Auth.isAdmin() && !Auth.id().equals(resourceOwnerId)) {
                passed = false;
                failMessage = "Not the resource owner";
            }
            return this;
        }

        /**
         * Adds custom verification.
         */
        public GuardChain when(boolean condition, String message) {
            if (passed && !condition) {
                passed = false;
                failMessage = message;
            }
            return this;
        }

        /**
         * Allows passing if any previous check passed.
         * Resets state to try alternative.
         */
        public GuardChain or() {
            if (passed) {
                return this; // Already passed, ignore rest
            }
            passed = true; // Reset to try alternative
            return this;
        }

        /**
         * Finalizes and throws exception if no check passed.
         * 
         * @throws AccessDeniedException if all checks failed
         */
        public void authorize() {
            if (!passed) {
                throw new AccessDeniedException(failMessage);
            }
        }
    }
}
