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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.DemoTestConfig;
import ao.sudojed.lss.jwt.JwtService;

/**
 * Testes de integração para ProfileController.
 * Testa os endpoints de perfil: /api/profile, /api/me
 */
@SpringBootTest(classes = DemoTestConfig.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class ProfileControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    private static String userToken;
    private static String adminToken;

    @BeforeAll
    static void setupTokens(@Autowired JwtService jwtService) {
        // Criar token de usuário regular
        LazyUser user = LazyUser.builder()
                .id("profile-user-123")
                .username("profileuser")
                .roles("USER")
                .claim("email", "profile@example.com")
                .claim("displayName", "Profile User")
                .build();
        userToken = jwtService.createTokens(user).accessToken();

        // Criar token de admin
        LazyUser admin = LazyUser.builder()
                .id("profile-admin-456")
                .username("profileadmin")
                .roles("ADMIN", "USER")
                .claim("email", "admin@example.com")
                .claim("displayName", "Admin User")
                .build();
        adminToken = jwtService.createTokens(admin).accessToken();
    }

    // ==================== GET /api/profile Tests ====================

    @Test
    @Order(1)
    @DisplayName("GET /api/profile - deve retornar 401 sem token")
    void profileShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/profile"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(2)
    @DisplayName("GET /api/profile - deve retornar perfil com token válido")
    void profileShouldReturnProfileWithValidToken() throws Exception {
        mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("profile-user-123"))
                .andExpect(jsonPath("$.username").value("profileuser"))
                .andExpect(jsonPath("$.email").value("profile@example.com"))
                .andExpect(jsonPath("$.isAdmin").value(false));
    }

    @Test
    @Order(3)
    @DisplayName("GET /api/profile - deve mostrar isAdmin=true para admin")
    void profileShouldShowIsAdminForAdmin() throws Exception {
        mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("profileadmin"))
                .andExpect(jsonPath("$.isAdmin").value(true));
    }

    // ==================== GET /api/me Tests ====================

    @Test
    @Order(4)
    @DisplayName("GET /api/me - deve retornar 401 sem token")
    void meShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    @DisplayName("GET /api/me - deve retornar dados do usuário com Auth facade")
    void meShouldReturnUserDataWithAuthFacade() throws Exception {
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value("profile-user-123"))
                .andExpect(jsonPath("$.username").value("profileuser"))
                .andExpect(jsonPath("$.email").value("profile@example.com"))
                .andExpect(jsonPath("$.isAdmin").value(false))
                .andExpect(jsonPath("$.isGuest").value(false));
    }

    // ==================== PUT /api/profile Tests ====================

    @Test
    @Order(6)
    @DisplayName("PUT /api/profile - deve retornar 401 sem token")
    void updateProfileShouldReturn401WithoutToken() throws Exception {
        String updateRequest = """
            {
                "displayName": "New Name"
            }
            """;

        mockMvc.perform(put("/api/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(updateRequest))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(7)
    @DisplayName("PUT /api/profile - deve retornar 404 para usuário não encontrado no banco")
    void updateProfileShouldReturn404ForUserNotInDatabase() throws Exception {
        // O usuário existe no token mas não no UserService (in-memory database)
        String updateRequest = """
            {
                "displayName": "New Display Name",
                "email": "newemail@example.com"
            }
            """;

        mockMvc.perform(put("/api/profile")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(updateRequest)
                        .header("Authorization", "Bearer " + userToken))
                .andExpect(status().isNotFound());
    }

    // ==================== Invalid Token Tests ====================

    @Test
    @Order(8)
    @DisplayName("GET /api/profile - deve retornar 401 com token inválido")
    void profileShouldReturn401WithInvalidToken() throws Exception {
        mockMvc.perform(get("/api/profile")
                        .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(9)
    @DisplayName("GET /api/profile - comportamento com token sem prefixo Bearer")
    void profileBehaviorWithoutBearerPrefix() throws Exception {
        // O comportamento pode variar - alguns sistemas aceitam, outros não
        // Este teste verifica que o endpoint responde (pode ser 200 ou 401)
        mockMvc.perform(get("/api/profile")
                        .header("Authorization", userToken))
                .andExpect(status().isOk()); // LSS aceita token mesmo sem Bearer
    }
}
