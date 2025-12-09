package ao.sudojed.lss.core;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Represents the authenticated user in the LazySpringSecurity context.
 * Simplified wrapper over Spring Security Principal.
 * 
 * <h2>Accessing Current User</h2>
 * <pre>{@code
 * @GetMapping("/profile")
 * public User profile(LazyUser user) {  // Automatically injected
 *     return userService.findById(user.getId());
 * }
 * 
 * // Or via static context
 * LazyUser user = LazySecurityContext.getCurrentUser();
 * }</pre>
 *
 * @author Sudojed Team
 */
public class LazyUser implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String id;
    private final String username;
    private final Set<String> roles;
    private final Set<String> permissions;
    private final Map<String, Object> claims;
    private final boolean authenticated;

    private LazyUser(Builder builder) {
        this.id = builder.id;
        this.username = builder.username;
        this.roles = Collections.unmodifiableSet(new HashSet<>(builder.roles));
        this.permissions = Collections.unmodifiableSet(new HashSet<>(builder.permissions));
        this.claims = Collections.unmodifiableMap(new HashMap<>(builder.claims));
        this.authenticated = builder.authenticated;
    }

    // ==================== Getters ====================

    public String getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    // ==================== Role/Permission Checks ====================

    /**
     * Checks if has a specific role.
     */
    public boolean hasRole(String role) {
        return roles.contains(normalizeRole(role));
    }

    /**
     * Checks if has ANY of the roles.
     */
    public boolean hasAnyRole(String... roles) {
        return Arrays.stream(roles)
                .map(this::normalizeRole)
                .anyMatch(this.roles::contains);
    }

    /**
     * Checks if has ALL the roles.
     */
    
    public boolean hasAllRoles(String... roles) {
        return Arrays.stream(roles)
                .map(this::normalizeRole)
                .allMatch(this.roles::contains);
    }

    /**
     * Checks if has a specific permission.
     */
    public boolean hasPermission(String permission) {
        return permissions.contains(permission);
    }

    /**
     * Checks if is admin.
     */
    public boolean isAdmin() {
        return hasRole("ADMIN");
    }

    // ==================== Claims ====================

    /**
     * Gets a specific claim from the token.
     */
    @SuppressWarnings("unchecked")
    public <T> T getClaim(String key) {
        return (T) claims.get(key);
    }

    /**
     * Gets a claim with default value.
     */
    @SuppressWarnings("unchecked")
    public <T> T getClaim(String key, T defaultValue) {
        return (T) claims.getOrDefault(key, defaultValue);
    }

    /**
     * Checks if a claim exists.
     */
    public boolean hasClaim(String key) {
        return claims.containsKey(key);
    }

    // ==================== Utilities ====================

    private String normalizeRole(String role) {
        if (role == null) return "";
        String normalized = role.toUpperCase();
        return normalized.startsWith("ROLE_") ? normalized.substring(5) : normalized;
    }

    /**
     * Creates an anonymous user.
     */
    public static LazyUser anonymous() {
        return LazyUser.builder()
                .id("anonymous")
                .username("anonymous")
                .authenticated(false)
                .build();
    }

    /**
     * Creates a builder for LazyUser.
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        return String.format("LazyUser{id='%s', username='%s', roles=%s, authenticated=%s}",
                id, username, roles, authenticated);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LazyUser lazyUser = (LazyUser) o;
        return Objects.equals(id, lazyUser.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    // ==================== Builder ====================

    public static class Builder {
        private String id;
        private String username;
        private Set<String> roles = new HashSet<>();
        private Set<String> permissions = new HashSet<>();
        private Map<String, Object> claims = new HashMap<>();
        private boolean authenticated = true;

        public Builder id(String id) {
            this.id = id;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder role(String role) {
            this.roles.add(role);
            return this;
        }

        public Builder roles(Collection<String> roles) {
            this.roles.addAll(roles);
            return this;
        }

        public Builder roles(String... roles) {
            this.roles.addAll(Arrays.asList(roles));
            return this;
        }

        public Builder permission(String permission) {
            this.permissions.add(permission);
            return this;
        }

        public Builder permissions(Collection<String> permissions) {
            this.permissions.addAll(permissions);
            return this;
        }

        public Builder permissions(String... permissions) {
            this.permissions.addAll(Arrays.asList(permissions));
            return this;
        }

        public Builder claim(String key, Object value) {
            this.claims.put(key, value);
            return this;
        }

        public Builder claims(Map<String, Object> claims) {
            this.claims.putAll(claims);
            return this;
        }

        public Builder authenticated(boolean authenticated) {
            this.authenticated = authenticated;
            return this;
        }

        public LazyUser build() {
            return new LazyUser(this);
        }
    }
}
