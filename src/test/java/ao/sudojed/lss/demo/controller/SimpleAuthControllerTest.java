package ao.sudojed.lss.demo.controller;

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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.demo.DemoTestConfig;
import ao.sudojed.lss.jwt.JwtService;

/**
 * Testes de integração para SimpleAuthController.
 * 
 * NOTA: O SimpleAuthController usa os endpoints /api/v2/auth/** que NÃO estão
 * configurados como públicos na configuração padrão do DemoTestConfig.
 * 
 * Os endpoints /api/v2/auth/** usam anotações @Login, @Register, @RefreshToken
 * que herdam de @Public, mas também precisam estar nos publicPaths do @EnableLazySecurity.
 * 
 * Este teste verifica que os endpoints exigem configuração correta de publicPaths.
 */
@SpringBootTest(classes = DemoTestConfig.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class SimpleAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    // ==================== Testes verificando que endpoints precisam de publicPaths ====================
    
    /**
     * Verifica que os endpoints /api/v2/auth/** retornam 401 quando não estão
     * nos publicPaths da configuração @EnableLazySecurity.
     * 
     * Para fazer funcionar, adicionar "/api/v2/auth/**" aos publicPaths.
     */
    @Test
    @Order(1)
    @DisplayName("POST /api/v2/auth/login - deve exigir que path esteja nos publicPaths")
    void loginEndpointRequiresPublicPathsConfiguration() throws Exception {
        String loginRequest = """
            {
                "username": "john",
                "password": "123456"
            }
            """;

        // Endpoint não está nos publicPaths, deve retornar 401
        mockMvc.perform(post("/api/v2/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(2)
    @DisplayName("POST /api/v2/auth/register - deve exigir que path esteja nos publicPaths")
    void registerEndpointRequiresPublicPathsConfiguration() throws Exception {
        String registerRequest = """
            {
                "username": "newuser",
                "email": "new@example.com",
                "password": "password123"
            }
            """;

        // Endpoint não está nos publicPaths, deve retornar 401
        mockMvc.perform(post("/api/v2/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequest))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(3)
    @DisplayName("POST /api/v2/auth/refresh - deve exigir que path esteja nos publicPaths")
    void refreshEndpointRequiresPublicPathsConfiguration() throws Exception {
        LazyUser user = LazyUser.builder()
                .id("test-user")
                .username("testuser")
                .roles("USER")
                .build();
        String refreshToken = jwtService.createTokens(user).refreshToken();

        String refreshRequest = String.format("""
            {
                "refresh_token": "%s"
            }
            """, refreshToken);

        // Endpoint não está nos publicPaths, deve retornar 401
        mockMvc.perform(post("/api/v2/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshRequest))
                .andExpect(status().isUnauthorized());
    }

    // ==================== Comparação com endpoints públicos configurados ====================

    @Test
    @Order(4)
    @DisplayName("POST /auth/login - endpoints em /auth/** funcionam (estão nos publicPaths)")
    void authPathsAreConfiguredAsPublic() throws Exception {
        String loginRequest = """
            {
                "username": "john",
                "password": "123456"
            }
            """;

        // /auth/** está nos publicPaths, deve funcionar
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists());
    }

    @Test
    @Order(5)
    @DisplayName("POST /auth/register - endpoints em /auth/** funcionam (estão nos publicPaths)")
    void authRegisterPathIsConfiguredAsPublic() throws Exception {
        String registerRequest = """
            {
                "username": "simpletest",
                "email": "simpletest@example.com",
                "password": "password123"
            }
            """;

        // /auth/** está nos publicPaths, deve funcionar
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequest))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").exists());
    }
}
