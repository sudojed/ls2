package ao.sudojed.lss.demo.controller;

import java.util.Map;

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
import org.springframework.test.web.servlet.MvcResult;
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
 * Testes de integração para OrderController.
 * Testa os endpoints de pedidos: /api/orders, /api/users/{userId}/orders, etc.
 */
@SpringBootTest(classes = DemoTestConfig.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class OrderControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private ObjectMapper objectMapper;

    private static String user1Token;
    private static String user2Token;
    private static String adminToken;
    private static String managerToken;
    private static String createdOrderId;

    @BeforeAll
    static void setupTokens(@Autowired JwtService jwtService) {
        // Usuário 1
        LazyUser user1 = LazyUser.builder()
                .id("order-user-1")
                .username("orderuser1")
                .roles("USER")
                .build();
        user1Token = jwtService.createTokens(user1).accessToken();

        // Usuário 2
        LazyUser user2 = LazyUser.builder()
                .id("order-user-2")
                .username("orderuser2")
                .roles("USER")
                .build();
        user2Token = jwtService.createTokens(user2).accessToken();

        // Admin
        LazyUser admin = LazyUser.builder()
                .id("order-admin")
                .username("orderadmin")
                .roles("ADMIN", "USER")
                .build();
        adminToken = jwtService.createTokens(admin).accessToken();

        // Manager
        LazyUser manager = LazyUser.builder()
                .id("order-manager")
                .username("ordermanager")
                .roles("MANAGER", "USER")
                .build();
        managerToken = jwtService.createTokens(manager).accessToken();
    }

    // ==================== GET /api/orders Tests ====================

    @Test
    @Order(1)
    @DisplayName("GET /api/orders - deve retornar 401 sem token")
    void getOrdersShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/orders"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(2)
    @DisplayName("GET /api/orders - deve retornar lista de pedidos do usuário")
    void getOrdersShouldReturnUserOrders() throws Exception {
        mockMvc.perform(get("/api/orders")
                        .header("Authorization", "Bearer " + user1Token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("order-user-1"))
                .andExpect(jsonPath("$.username").value("orderuser1"))
                .andExpect(jsonPath("$.orders").isArray());
    }

    // ==================== POST /api/orders Tests ====================

    @Test
    @Order(3)
    @DisplayName("POST /api/orders - deve retornar 401 sem token")
    void createOrderShouldReturn401WithoutToken() throws Exception {
        String orderRequest = """
            {
                "product": "Laptop",
                "price": 1500.00,
                "quantity": 1
            }
            """;

        mockMvc.perform(post("/api/orders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(orderRequest))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(4)
    @DisplayName("POST /api/orders - deve criar novo pedido com sucesso")
    void createOrderShouldCreateOrder() throws Exception {
        String orderRequest = """
            {
                "product": "Gaming Mouse",
                "price": 99.99,
                "quantity": 2
            }
            """;

        MvcResult result = mockMvc.perform(post("/api/orders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(orderRequest)
                        .header("Authorization", "Bearer " + user1Token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Order created successfully!"))
                .andExpect(jsonPath("$.order.product").value("Gaming Mouse"))
                .andExpect(jsonPath("$.order.total").value(199.98))
                .andExpect(jsonPath("$.order.status").value("PENDING"))
                .andExpect(jsonPath("$.createdBy").value("orderuser1"))
                .andReturn();

        // Salvar orderId para testes posteriores
        String responseBody = result.getResponse().getContentAsString();
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        Map<String, Object> order = (Map<String, Object>) response.get("order");
        createdOrderId = (String) order.get("orderId");
    }

    // ==================== GET /api/users/{userId}/orders Tests (Owner) ====================

    @Test
    @Order(5)
    @DisplayName("GET /api/users/{userId}/orders - deve retornar 401 sem token")
    void getUserOrdersShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/users/order-user-1/orders"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(6)
    @DisplayName("GET /api/users/{userId}/orders - usuário pode ver seus próprios pedidos")
    void getUserOrdersShouldAllowOwner() throws Exception {
        mockMvc.perform(get("/api/users/order-user-1/orders")
                        .header("Authorization", "Bearer " + user1Token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("order-user-1"))
                .andExpect(jsonPath("$.isOwner").value(true))
                .andExpect(jsonPath("$.accessedBy").value("orderuser1"));
    }

    @Test
    @Order(7)
    @DisplayName("GET /api/users/{userId}/orders - usuário NÃO pode ver pedidos de outro")
    void getUserOrdersShouldDenyNonOwner() throws Exception {
        mockMvc.perform(get("/api/users/order-user-1/orders")
                        .header("Authorization", "Bearer " + user2Token))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(8)
    @DisplayName("GET /api/users/{userId}/orders - admin pode ver pedidos de qualquer usuário")
    void getUserOrdersShouldAllowAdminBypass() throws Exception {
        mockMvc.perform(get("/api/users/order-user-1/orders")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("order-user-1"))
                .andExpect(jsonPath("$.isAdmin").value(true))
                .andExpect(jsonPath("$.accessedBy").value("orderadmin"));
    }

    // ==================== DELETE /api/orders/{orderId} Tests ====================

    @Test
    @Order(9)
    @DisplayName("DELETE /api/orders/{orderId} - deve retornar 401 sem token")
    void cancelOrderShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(delete("/api/orders/ORD-001"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(10)
    @DisplayName("DELETE /api/orders/{orderId} - deve cancelar pedido do próprio usuário")
    void cancelOrderShouldCancelOwnOrder() throws Exception {
        // Primeiro criar um pedido
        String orderRequest = """
            {
                "product": "Headphones",
                "price": 50.00
            }
            """;

        MvcResult createResult = mockMvc.perform(post("/api/orders")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(orderRequest)
                        .header("Authorization", "Bearer " + user1Token))
                .andExpect(status().isOk())
                .andReturn();

        String responseBody = createResult.getResponse().getContentAsString();
        Map<String, Object> response = objectMapper.readValue(responseBody, Map.class);
        Map<String, Object> order = (Map<String, Object>) response.get("order");
        String orderId = (String) order.get("orderId");

        // Agora cancelar o pedido
        mockMvc.perform(delete("/api/orders/" + orderId)
                        .header("Authorization", "Bearer " + user1Token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Order cancelled successfully"))
                .andExpect(jsonPath("$.orderId").value(orderId));
    }

    @Test
    @Order(11)
    @DisplayName("DELETE /api/orders/{orderId} - usuário não pode cancelar pedido de outro")
    void cancelOrderShouldDenyNonOwner() throws Exception {
        mockMvc.perform(delete("/api/orders/ORD-001")
                        .header("Authorization", "Bearer " + user2Token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.error").value("ORDER_NOT_FOUND"));
    }

    // ==================== GET /api/orders/all Tests (anyRole) ====================

    @Test
    @Order(12)
    @DisplayName("GET /api/orders/all - deve retornar 401 sem token")
    void getAllOrdersShouldReturn401WithoutToken() throws Exception {
        mockMvc.perform(get("/api/orders/all"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(13)
    @DisplayName("GET /api/orders/all - usuário regular não tem acesso")
    void getAllOrdersShouldDenyRegularUser() throws Exception {
        mockMvc.perform(get("/api/orders/all")
                        .header("Authorization", "Bearer " + user1Token))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(14)
    @DisplayName("GET /api/orders/all - admin pode ver todos os pedidos")
    void getAllOrdersShouldAllowAdmin() throws Exception {
        mockMvc.perform(get("/api/orders/all")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orders").isArray())
                .andExpect(jsonPath("$.requestedBy").value("orderadmin"));
    }

    @Test
    @Order(15)
    @DisplayName("GET /api/orders/all - manager pode ver todos os pedidos")
    void getAllOrdersShouldAllowManager() throws Exception {
        mockMvc.perform(get("/api/orders/all")
                        .header("Authorization", "Bearer " + managerToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.orders").isArray())
                .andExpect(jsonPath("$.requestedBy").value("ordermanager"));
    }
}
