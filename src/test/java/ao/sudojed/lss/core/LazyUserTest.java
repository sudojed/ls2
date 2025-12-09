package ao.sudojed.lss.core;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for LazyUser.
 */
class LazyUserTest {

    @Test
    @DisplayName("Should create user with builder")
    void shouldCreateUserWithBuilder() {
        // When
        LazyUser user = LazyUser.builder()
                .id("user-123")
                .username("john.doe")
                .roles("USER", "ADMIN")
                .permissions("posts:read", "posts:write")
                .claim("email", "john@example.com")
                .authenticated(true)
                .build();

        // Then
        assertEquals("user-123", user.getId());
        assertEquals("john.doe", user.getUsername());
        assertTrue(user.isAuthenticated());
        assertEquals(Set.of("USER", "ADMIN"), user.getRoles());
        assertEquals(Set.of("posts:read", "posts:write"), user.getPermissions());
        assertEquals("john@example.com", user.getClaim("email"));
    }

    @Test
    @DisplayName("Should check role correctly")
    void shouldCheckRoleCorrectly() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER", "VERIFIED")
                .build();

        // Then
        assertTrue(user.hasRole("USER"));
        assertTrue(user.hasRole("VERIFIED"));
        assertFalse(user.hasRole("ADMIN"));
        
        // Case insensitive
        assertTrue(user.hasRole("user"));
        assertTrue(user.hasRole("User"));
    }

    @Test
    @DisplayName("Should check hasAnyRole correctly")
    void shouldCheckHasAnyRole() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER")
                .build();

        // Then
        assertTrue(user.hasAnyRole("USER", "ADMIN"));
        assertTrue(user.hasAnyRole("ADMIN", "USER", "MANAGER"));
        assertFalse(user.hasAnyRole("ADMIN", "MANAGER"));
    }

    @Test
    @DisplayName("Should check hasAllRoles correctly")
    void shouldCheckHasAllRoles() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER", "VERIFIED", "PREMIUM")
                .build();

        // Then
        assertTrue(user.hasAllRoles("USER", "VERIFIED"));
        assertTrue(user.hasAllRoles("USER", "VERIFIED", "PREMIUM"));
        assertFalse(user.hasAllRoles("USER", "ADMIN"));
    }

    @Test
    @DisplayName("Should check permissions")
    void shouldCheckPermissions() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .permissions("posts:read", "posts:write", "users:read")
                .build();

        // Then
        assertTrue(user.hasPermission("posts:read"));
        assertTrue(user.hasPermission("posts:write"));
        assertFalse(user.hasPermission("users:delete"));
    }

    @Test
    @DisplayName("Should identify admin")
    void shouldIdentifyAdmin() {
        // Given
        LazyUser admin = LazyUser.builder()
                .id("1")
                .username("admin")
                .roles("ADMIN")
                .build();

        LazyUser user = LazyUser.builder()
                .id("2")
                .username("user")
                .roles("USER")
                .build();

        // Then
        assertTrue(admin.isAdmin());
        assertFalse(user.isAdmin());
    }

    @Test
    @DisplayName("Should create anonymous user")
    void shouldCreateAnonymousUser() {
        // When
        LazyUser anonymous = LazyUser.anonymous();

        // Then
        assertEquals("anonymous", anonymous.getId());
        assertEquals("anonymous", anonymous.getUsername());
        assertFalse(anonymous.isAuthenticated());
        assertTrue(anonymous.getRoles().isEmpty());
    }

    @Test
    @DisplayName("Should normalize roles with ROLE_ prefix")
    void shouldNormalizeRolesWithPrefix() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .roles("USER")
                .build();

        // Then - should accept with or without prefix
        assertTrue(user.hasRole("USER"));
        assertTrue(user.hasRole("ROLE_USER"));
    }

    @Test
    @DisplayName("Should return claim with default value")
    void shouldReturnClaimWithDefault() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .claim("existing", "value")
                .build();

        // Then
        assertEquals("value", user.getClaim("existing", "default"));
        assertEquals("default", user.getClaim("nonexistent", "default"));
    }

    @Test
    @DisplayName("Should check claim existence")
    void shouldCheckClaimExistence() {
        // Given
        LazyUser user = LazyUser.builder()
                .id("1")
                .username("test")
                .claim("email", "test@example.com")
                .build();

        // Then
        assertTrue(user.hasClaim("email"));
        assertFalse(user.hasClaim("phone"));
    }

    @Test
    @DisplayName("Should implement equals and hashCode based on id")
    void shouldImplementEqualsAndHashCode() {
        // Given
        LazyUser user1 = LazyUser.builder().id("123").username("john").build();
        LazyUser user2 = LazyUser.builder().id("123").username("jane").build();
        LazyUser user3 = LazyUser.builder().id("456").username("john").build();

        // Then
        assertEquals(user1, user2); // same id
        assertNotEquals(user1, user3); // different id
        assertEquals(user1.hashCode(), user2.hashCode());
    }
}
