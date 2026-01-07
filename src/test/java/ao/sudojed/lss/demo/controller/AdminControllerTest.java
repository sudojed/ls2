package ao.sudojed.lss.demo.controller;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.DemoTestConfig;
import ao.sudojed.lss.jwt.JwtService;

/**
 * Testes de integração para AdminController.
 * Testa os endpoints administrativos: /api/admin/users, /api/admin/dashboard, etc.
 */
@SpringBootTest(classes = DemoTestConfig.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdminControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    private static String userToken;
    private static String adminToken;
    private static String managerToken;

    @BeforeAll
    static void setupTokens(@Autowired JwtService jwtService) {
        // Token de usuário regular
        LazyUser user = LazyUser.builder()
                .id("admin-test-user-123")
                .username("regularuser")
                .roles("USER")
                .build();
        userToken = jwtService.createTokens(user).accessToken();

        // Token de admin
        LazyUser admin = LazyUser.builder()
                .id("admin-test-admin-456")
                .username("testadmin")
                .roles("ADMIN", "USER")
                .build();
        adminToken = jwtService.createTokens(admin).accessToken();

        // Token de manager (para testar anyRole)
        LazyUser manager = LazyUser.builder()
                .id("admin-test-manager-789")
                .username("testmanager")
                .roles("MANAGER", "USER")
                .build();
        managerToken = jwtService.createTokens(manager).accessToken();
    }

    // ==================== GET /api/admin/users Tests ====================

    @Test
    @Order(1)
    @DisplayName("GET /api/admin/users - deve retornar 401 sem token")
    void listUsersShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(2)
    @DisplayName("GET /api/admin/users - deve retornar 403 para usuário não-admin")
    void listUsersShouldReturn403ForNonAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(3)
    @DisplayName("GET /api/admin/users - deve retornar lista de usuários para admin")
    void listUsersShouldReturnUsersForAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/users")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").exists())
                .andExpect(jsonPath("$.users").isArray())
                .andExpect(jsonPath("$.requestedBy").value("testadmin"));
    }

    // ==================== GET /api/admin/users/{userId} Tests ====================

    @Test
    @Order(4)
    @DisplayName("GET /api/admin/users/{userId} - deve retornar 401 sem token")
    void getUserShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/admin/users/any-user-id"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    @DisplayName("GET /api/admin/users/{userId} - deve retornar 403 para não-admin")
    void getUserShouldReturn403ForNonAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/users/any-user-id")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(6)
    @DisplayName("GET /api/admin/users/{userId} - deve retornar 404 para usuário inexistente")
    void getUserShouldReturn404ForNonExistentUser() throws Exception {
        mockMvc.perform(get("/api/admin/users/nonexistent-user-id")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    // ==================== DELETE /api/admin/users/{userId} Tests ====================

    @Test
    @Order(7)
    @DisplayName("DELETE /api/admin/users/{userId} - deve retornar 401 sem token")
    void deleteUserShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(delete("/api/admin/users/any-user-id"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(8)
    @DisplayName("DELETE /api/admin/users/{userId} - deve retornar 403 para não-admin")
    void deleteUserShouldReturn403ForNonAdmin() throws Exception {
        mockMvc.perform(delete("/api/admin/users/any-user-id")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(9)
    @DisplayName("DELETE /api/admin/users/{userId} - não deve permitir auto-exclusão")
    void deleteUserShouldPreventSelfDeletion() throws Exception {
        mockMvc.perform(delete("/api/admin/users/admin-test-admin-456")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("CANNOT_DELETE_SELF"));
    }

    @Test
    @Order(10)
    @DisplayName("DELETE /api/admin/users/{userId} - deve retornar 404 para usuário inexistente")
    void deleteUserShouldReturn404ForNonExistentUser() throws Exception {
        mockMvc.perform(delete("/api/admin/users/nonexistent-user-id")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isNotFound());
    }

    // ==================== POST /api/admin/users/{userId}/roles Tests ====================

    @Test
    @Order(11)
    @DisplayName("POST /api/admin/users/{userId}/roles - deve retornar 401 sem token")
    void addRoleShouldReturn401WithoutToken() throws Exception {
        String roleRequest = """
            {
                "role": "MANAGER"
            }
            """;

        mockMvc.perform(post("/api/admin/users/any-user-id/roles")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(roleRequest))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(12)
    @DisplayName("POST /api/admin/users/{userId}/roles - deve retornar 403 para não-admin")
    void addRoleShouldReturn403ForNonAdmin() throws Exception {
        String roleRequest = """
            {
                "role": "MANAGER"
            }
            """;

        mockMvc.perform(post("/api/admin/users/any-user-id/roles")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(roleRequest)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(13)
    @DisplayName("POST /api/admin/users/{userId}/roles - deve retornar 400 sem campo role")
    void addRoleShouldReturn400WithoutRoleField() throws Exception {
        String roleRequest = """
            {
            }
            """;

        mockMvc.perform(post("/api/admin/users/any-user-id/roles")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(roleRequest)
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MISSING_ROLE"));
    }

    // ==================== GET /api/admin/dashboard Tests ====================

    @Test
    @Order(14)
    @DisplayName("GET /api/admin/dashboard - deve retornar 401 sem token")
    void dashboardShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(15)
    @DisplayName("GET /api/admin/dashboard - deve retornar 403 para não-admin")
    void dashboardShouldReturn403ForNonAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(16)
    @DisplayName("GET /api/admin/dashboard - deve retornar estatísticas para admin")
    void dashboardShouldReturnStatsForAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/dashboard")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.stats").exists())
                .andExpect(jsonPath("$.stats.totalUsers").exists())
                .andExpect(jsonPath("$.admin.username").value("testadmin"))
                .andExpect(jsonPath("$.admin.isAdmin").value(true));
    }

    // ==================== GET /api/admin/reports Tests (anyRole) ====================

    @Test
    @Order(17)
    @DisplayName("GET /api/admin/reports - deve retornar 401 sem token")
    void reportsShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/admin/reports"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(18)
    @DisplayName("GET /api/admin/reports - deve retornar 403 para usuário regular")
    void reportsShouldReturn403ForRegularUser() throws Exception {
        mockMvc.perform(get("/api/admin/reports")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(19)
    @DisplayName("GET /api/admin/reports - deve aceitar ADMIN")
    void reportsShouldAcceptAdmin() throws Exception {
        mockMvc.perform(get("/api/admin/reports")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reports").isArray())
                .andExpect(jsonPath("$.generatedBy").value("testadmin"));
    }

    @Test
    @Order(20)
    @DisplayName("GET /api/admin/reports - deve aceitar MANAGER")
    void reportsShouldAcceptManager() throws Exception {
        mockMvc.perform(get("/api/admin/reports")
                        .header("Authorization", "Bearer " + managerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reports").isArray())
                .andExpect(jsonPath("$.generatedBy").value("testmanager"));
    }
}
