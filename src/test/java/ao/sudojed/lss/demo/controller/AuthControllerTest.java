package ao.sudojed.lss.demo.controller;

import java.util.Map;

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
import org.springframework.test.web.servlet.MvcResult;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;

import ao.sudojed.lss.demo.DemoTestConfig;
import ao.sudojed.lss.jwt.JwtService;

/**
 * Testes de integração para AuthController.
 * Testa os endpoints de autenticação: health, register, login, refresh.
 */
@SpringBootTest(classes = DemoTestConfig.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    private static String refreshToken;

    // ==================== Health Check Tests ====================

    @Test
    @Order(1)
    @DisplayName("GET /auth/health - deve retornar status UP")
    void healthShouldReturnStatusUp() throws Exception {
        mockMvc.perform(get("/auth/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"))
                .andExpect(jsonPath("$.service").value("LSS Demo API"))
                .andExpect(jsonPath("$.version").value("1.0.0"));
    }

    // ==================== Registration Tests ====================

    @Test
    @Order(2)
    @DisplayName("POST /auth/register - deve criar novo usuário com sucesso")
    void registerShouldCreateNewUser() throws Exception {
        String registerRequest = """
            {
                "username": "testuser_auth",
                "email": "testuser_auth@example.com",
                "password": "password123"
            }
            """;

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequest))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message").value("User created successfully!"))
                .andExpect(jsonPath("$.userId").exists())
                .andExpect(jsonPath("$.username").value("testuser_auth"));
    }

    @Test
    @Order(3)
    @DisplayName("POST /auth/register - deve retornar 409 para usuário duplicado")
    void registerShouldReturn409ForDuplicateUser() throws Exception {
        // Tentar registrar o mesmo usuário novamente
        String registerRequest = """
            {
                "username": "testuser_auth",
                "email": "testuser_auth@example.com",
                "password": "password123"
            }
            """;

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequest))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("USER_EXISTS"));
    }

    // ==================== Login Tests ====================

    @Test
    @Order(4)
    @DisplayName("POST /auth/login - deve autenticar usuário e retornar tokens")
    void loginShouldReturnTokens() throws Exception {
        // Primeiro registrar o usuário para login
        String registerRequest = """
            {
                "username": "loginuser",
                "email": "login@example.com",
                "password": "mypassword"
            }
            """;
        mockMvc.perform(post("/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(registerRequest));

        // Agora fazer login
        String loginRequest = """
            {
                "username": "loginuser",
                "password": "mypassword"
            }
            """;

        MvcResult result = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").exists())
                .andReturn();

        // Salvar refresh_token para teste posterior
        String responseBody = result.getResponse().getContentAsString();
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        refreshToken = (String) response.get("refresh_token");
    }

    @Test
    @Order(5)
    @DisplayName("POST /auth/login - deve retornar 401 para credenciais inválidas")
    void loginShouldReturn401ForInvalidCredentials() throws Exception {
        String loginRequest = """
            {
                "username": "loginuser",
                "password": "wrongpassword"
            }
            """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"));
    }

    @Test
    @Order(6)
    @DisplayName("POST /auth/login - deve retornar 401 para usuário inexistente")
    void loginShouldReturn401ForNonExistentUser() throws Exception {
        String loginRequest = """
            {
                "username": "nonexistentuser",
                "password": "password"
            }
            """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_CREDENTIALS"));
    }

    @Test
    @Order(7)
    @DisplayName("POST /auth/login - deve autenticar usuários demo existentes")
    void loginShouldAuthenticateDemoUsers() throws Exception {
        // Admin user (criado no UserService)
        String adminLogin = """
            {
                "username": "admin",
                "password": "admin123"
            }
            """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(adminLogin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists());

        // John user
        String johnLogin = """
            {
                "username": "john",
                "password": "123456"
            }
            """;

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(johnLogin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists());
    }

    // ==================== Refresh Token Tests ====================

    @Test
    @Order(8)
    @DisplayName("POST /auth/refresh - deve retornar novos tokens")
    void refreshShouldReturnNewTokens() throws Exception {
        // Primeiro fazer login para obter um refresh_token válido
        String loginRequest = """
            {
                "username": "admin",
                "password": "admin123"
            }
            """;
        
        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginRequest))
                .andExpect(status().isOk())
                .andReturn();
        
        String loginResponse = loginResult.getResponse().getContentAsString();
        Map<String, Object> loginData = objectMapper.readValue(loginResponse, Map.class);
        String validRefreshToken = (String) loginData.get("refresh_token");

        String refreshRequest = String.format("""
            {
                "refresh_token": "%s"
            }
            """, validRefreshToken);

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").exists())
                .andExpect(jsonPath("$.refresh_token").exists());
    }

    @Test
    @Order(9)
    @DisplayName("POST /auth/refresh - deve retornar 400 sem refresh_token")
    void refreshShouldReturn400WithoutToken() throws Exception {
        String refreshRequest = """
            {
            }
            """;

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshRequest))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("MISSING_TOKEN"));
    }

    @Test
    @Order(10)
    @DisplayName("POST /auth/refresh - deve retornar 401 com token inválido")
    void refreshShouldReturn401WithInvalidToken() throws Exception {
        String refreshRequest = """
            {
                "refresh_token": "invalid.token.here"
            }
            """;

        mockMvc.perform(post("/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshRequest))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("INVALID_REFRESH_TOKEN"));
    }
}
