package ao.sudojed.lss.demo.service;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.facade.Auth;

/**
 * Testes unitários para UserService.
 * Testa as operações de CRUD de usuários.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class UserServiceTest {

    private static UserService userService;

    @BeforeAll
    static void setup() {
        userService = new UserService();
    }

    // ==================== createUser Tests ====================

    @Test
    @Order(1)
    @DisplayName("createUser - deve criar usuário com sucesso")
    void createUserShouldCreateUser() {
        User user = userService.createUser("testuser", "test@example.com", "password123");

        assertNotNull(user);
        assertNotNull(user.getId());
        assertTrue(user.getId().startsWith("user-"));
        assertEquals("testuser", user.getUsername());
        assertEquals("test@example.com", user.getEmail());
        assertNotNull(user.getPasswordHash());
        assertNotEquals("password123", user.getPasswordHash()); // Senha deve estar hashada
        assertTrue(user.getRoles().contains("USER")); // Role padrão
        assertNotNull(user.getCreatedAt());
    }

    @Test
    @Order(2)
    @DisplayName("createUser - deve hashar senha corretamente")
    void createUserShouldHashPassword() {
        User user = userService.createUser("hashtest", "hash@example.com", "mypassword");

        // Verificar que a senha foi hashada
        assertNotNull(user.getPasswordHash());
        assertNotEquals("mypassword", user.getPasswordHash());
        
        // Verificar que o hash é válido usando Auth.checkPassword
        assertTrue(Auth.checkPassword("mypassword", user.getPasswordHash()));
        assertFalse(Auth.checkPassword("wrongpassword", user.getPasswordHash()));
    }

    // ==================== findByUsername Tests ====================

    @Test
    @Order(3)
    @DisplayName("findByUsername - deve encontrar usuário existente")
    void findByUsernameShouldFindExistingUser() {
        Optional<User> user = userService.findByUsername("testuser");

        assertTrue(user.isPresent());
        assertEquals("testuser", user.get().getUsername());
        assertEquals("test@example.com", user.get().getEmail());
    }

    @Test
    @Order(4)
    @DisplayName("findByUsername - deve retornar empty para usuário inexistente")
    void findByUsernameShouldReturnEmptyForNonExistent() {
        Optional<User> user = userService.findByUsername("nonexistentuser");

        assertTrue(user.isEmpty());
    }

    // ==================== findById Tests ====================

    @Test
    @Order(5)
    @DisplayName("findById - deve encontrar usuário existente")
    void findByIdShouldFindExistingUser() {
        // Primeiro obter o ID de um usuário existente
        Optional<User> userByName = userService.findByUsername("testuser");
        assertTrue(userByName.isPresent());
        String userId = userByName.get().getId();

        // Agora buscar pelo ID
        Optional<User> user = userService.findById(userId);

        assertTrue(user.isPresent());
        assertEquals(userId, user.get().getId());
        assertEquals("testuser", user.get().getUsername());
    }

    @Test
    @Order(6)
    @DisplayName("findById - deve retornar empty para ID inexistente")
    void findByIdShouldReturnEmptyForNonExistent() {
        Optional<User> user = userService.findById("nonexistent-id");

        assertTrue(user.isEmpty());
    }

    // ==================== findAll Tests ====================

    @Test
    @Order(7)
    @DisplayName("findAll - deve retornar lista de usuários")
    void findAllShouldReturnUserList() {
        List<User> users = userService.findAll();

        assertNotNull(users);
        assertFalse(users.isEmpty());
        // Deve conter pelo menos os usuários demo + usuários de teste
        assertTrue(users.size() >= 3); // admin, john, jane (demo users)
    }

    // ==================== save Tests ====================

    @Test
    @Order(8)
    @DisplayName("save - deve atualizar usuário existente")
    void saveShouldUpdateExistingUser() {
        Optional<User> userOpt = userService.findByUsername("testuser");
        assertTrue(userOpt.isPresent());

        User user = userOpt.get();
        user.setDisplayName("Test User Updated");
        user.setEmail("updated@example.com");

        User savedUser = userService.save(user);

        assertEquals("Test User Updated", savedUser.getDisplayName());
        assertEquals("updated@example.com", savedUser.getEmail());

        // Verificar que a atualização persistiu
        Optional<User> reloadedUser = userService.findByUsername("testuser");
        assertTrue(reloadedUser.isPresent());
        assertEquals("Test User Updated", reloadedUser.get().getDisplayName());
    }

    // ==================== deleteById Tests ====================

    @Test
    @Order(9)
    @DisplayName("deleteById - deve deletar usuário existente")
    void deleteByIdShouldDeleteExistingUser() {
        // Criar usuário para deletar
        User userToDelete = userService.createUser("deleteme", "delete@example.com", "password");
        String userId = userToDelete.getId();

        // Verificar que existe
        assertTrue(userService.findById(userId).isPresent());

        // Deletar
        boolean deleted = userService.deleteById(userId);

        assertTrue(deleted);
        assertTrue(userService.findById(userId).isEmpty());
        assertTrue(userService.findByUsername("deleteme").isEmpty());
    }

    @Test
    @Order(10)
    @DisplayName("deleteById - deve retornar false para ID inexistente")
    void deleteByIdShouldReturnFalseForNonExistent() {
        boolean deleted = userService.deleteById("nonexistent-id");

        assertFalse(deleted);
    }

    // ==================== Role Management Tests ====================

    @Test
    @Order(11)
    @DisplayName("addRole - deve adicionar role ao usuário")
    void addRoleShouldAddRoleToUser() {
        Optional<User> userOpt = userService.findByUsername("hashtest");
        assertTrue(userOpt.isPresent());

        User user = userOpt.get();
        user.addRole("MANAGER");
        userService.save(user);

        Optional<User> updatedUser = userService.findByUsername("hashtest");
        assertTrue(updatedUser.isPresent());
        assertTrue(updatedUser.get().getRoles().contains("USER"));
        assertTrue(updatedUser.get().getRoles().contains("MANAGER"));
    }

    // ==================== Demo Users Tests ====================

    @Test
    @Order(12)
    @DisplayName("Demo users - admin deve existir e ter role ADMIN")
    void demoUserAdminShouldExist() {
        Optional<User> admin = userService.findByUsername("admin");

        assertTrue(admin.isPresent());
        assertTrue(admin.get().getRoles().contains("ADMIN"));
        assertTrue(admin.get().getRoles().contains("USER"));
        assertEquals("Administrator", admin.get().getDisplayName());
        assertTrue(Auth.checkPassword("admin123", admin.get().getPasswordHash()));
    }

    @Test
    @Order(13)
    @DisplayName("Demo users - john deve existir")
    void demoUserJohnShouldExist() {
        Optional<User> john = userService.findByUsername("john");

        assertTrue(john.isPresent());
        assertTrue(john.get().getRoles().contains("USER"));
        assertEquals("John Doe", john.get().getDisplayName());
        assertTrue(Auth.checkPassword("123456", john.get().getPasswordHash()));
    }

    @Test
    @Order(14)
    @DisplayName("Demo users - jane deve existir e ter role MANAGER")
    void demoUserJaneShouldExist() {
        Optional<User> jane = userService.findByUsername("jane");

        assertTrue(jane.isPresent());
        assertTrue(jane.get().getRoles().contains("USER"));
        assertTrue(jane.get().getRoles().contains("MANAGER"));
        assertEquals("Jane Smith", jane.get().getDisplayName());
        assertTrue(Auth.checkPassword("123456", jane.get().getPasswordHash()));
    }
}
