package ao.sudojed.lss.demo.controller;

import ao.sudojed.lss.annotation.RateLimit;
import ao.sudojed.lss.annotation.Secured;
import ao.sudojed.lss.facade.Auth;
import ao.sudojed.lss.facade.Guard;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.bind.annotation.*;

/**
 * Order controller demonstrating Auth and Guard facades.
 *
 * Demonstrates:
 * - Auth.id(), Auth.username() to get user data
 * - Guard.owner() to verify resource ownership
 * - Guard.authenticated() to require login
 * - @RateLimit to limit requests
 *
 * @author Sudojed Team
 */
@RestController
@RequestMapping("/api")
public class OrderController {

    // Simulates order database
    private final Map<String, List<Map<String, Object>>> ordersByUser =
        new ConcurrentHashMap<>();

    public OrderController() {
        initializeSampleData();
    }

    private void initializeSampleData() {
        ordersByUser.put(
            "user-1",
            new ArrayList<>(
                List.of(
                    Map.of(
                        "orderId",
                        "ORD-001",
                        "product",
                        "Notebook",
                        "total",
                        2500.00,
                        "status",
                        "DELIVERED"
                    ),
                    Map.of(
                        "orderId",
                        "ORD-002",
                        "product",
                        "Mouse",
                        "total",
                        150.00,
                        "status",
                        "SHIPPED"
                    )
                )
            )
        );
        ordersByUser.put(
            "user-2",
            new ArrayList<>(
                List.of(
                    Map.of(
                        "orderId",
                        "ORD-003",
                        "product",
                        "Keyboard",
                        "total",
                        300.00,
                        "status",
                        "PENDING"
                    )
                )
            )
        );
    }

    /**
     * Lists logged user's orders.
     *
     * Uses Auth.id() and Auth.username() - no LazyUser parameter needed!
     */
    @Secured
    @RateLimit(requests = 10, window = 60)
    @GetMapping("/orders")
    public Map<String, Object> getMyOrders() {
        // Uses Auth facade instead of LazyUser parameter
        String userId = Auth.id();
        String username = Auth.username();

        List<Map<String, Object>> orders = ordersByUser.getOrDefault(
            userId,
            List.of()
        );

        return Map.of(
            "userId",
            userId,
            "username",
            username,
            "totalOrders",
            orders.size(),
            "orders",
            orders
        );
    }

    /**
     * Creates a new order.
     *
     * Demonstrates Guard.authenticated() for imperative verification.
     */
    @RateLimit(requests = 5, window = 60)
    @PostMapping("/orders")
    public Map<String, Object> createOrder(
        @RequestBody Map<String, Object> orderData
    ) {
        // Imperative authentication verification
        Guard.authenticated();

        String orderId =
            "ORD-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        Map<String, Object> newOrder = new HashMap<>();
        newOrder.put("orderId", orderId);
        newOrder.put("product", orderData.get("product"));
        newOrder.put("quantity", orderData.getOrDefault("quantity", 1));
        newOrder.put("price", orderData.get("price"));
        newOrder.put("total", calculateTotal(orderData));
        newOrder.put("status", "PENDING");
        newOrder.put("createdAt", LocalDateTime.now().toString());
        newOrder.put("userId", Auth.id()); // Auth facade!

        // Adds to "database"
        ordersByUser.computeIfAbsent(Auth.id(), k -> new ArrayList<>());
        List<Map<String, Object>> userOrders = new ArrayList<>(
            ordersByUser.get(Auth.id())
        );
        userOrders.add(newOrder);
        ordersByUser.put(Auth.id(), userOrders);

        return Map.of(
            "message",
            "Order created successfully!",
            "order",
            newOrder,
            "createdBy",
            Auth.username()
        );
    }

    /**
     * Gets orders from a specific user.
     *
     * Demonstrates Guard.owner() - checks if user is resource owner.
     * Admin has automatic bypass.
     */
    @GetMapping("/users/{userId}/orders")
    public Map<String, Object> getUserOrders(@PathVariable String userId) {
        // Requires authentication first
        Guard.authenticated();

        // Checks if owner OR admin (admin has automatic bypass)
        Guard.owner(userId);

        List<Map<String, Object>> orders = ordersByUser.getOrDefault(
            userId,
            List.of()
        );

        return Map.of(
            "userId",
            userId,
            "totalOrders",
            orders.size(),
            "orders",
            orders,
            "accessedBy",
            Auth.username(),
            "isOwner",
            userId.equals(Auth.id()),
            "isAdmin",
            Auth.isAdmin()
        );
    }

    /**
     * Cancels an order.
     *
     * Demonstrates conditional logic with Auth.isAdmin().
     */
    @DeleteMapping("/orders/{orderId}")
    public Map<String, Object> cancelOrder(@PathVariable String orderId) {
        Guard.authenticated();

        String userId = Auth.id();

        // Searches for current user's order
        List<Map<String, Object>> userOrders = ordersByUser.getOrDefault(
            userId,
            new ArrayList<>()
        );

        Optional<Map<String, Object>> orderOpt = userOrders
            .stream()
            .filter(o -> orderId.equals(o.get("orderId")))
            .findFirst();

        if (orderOpt.isEmpty()) {
            // If admin, can cancel any user's order
            if (Auth.isAdmin()) {
                for (var entry : ordersByUser.entrySet()) {
                    Optional<Map<String, Object>> found = entry
                        .getValue()
                        .stream()
                        .filter(o -> orderId.equals(o.get("orderId")))
                        .findFirst();
                    if (found.isPresent()) {
                        List<Map<String, Object>> updated = new ArrayList<>(
                            entry.getValue()
                        );
                        updated.remove(found.get());
                        ordersByUser.put(entry.getKey(), updated);
                        return Map.of(
                            "message",
                            "Order cancelled by admin",
                            "orderId",
                            orderId,
                            "cancelledBy",
                            Auth.username()
                        );
                    }
                }
            }

            return Map.of(
                "error",
                "ORDER_NOT_FOUND",
                "message",
                "Order not found or does not belong to you"
            );
        }

        // Removes the order
        List<Map<String, Object>> updated = new ArrayList<>(userOrders);
        updated.remove(orderOpt.get());
        ordersByUser.put(userId, updated);

        return Map.of(
            "message",
            "Order cancelled successfully",
            "orderId",
            orderId,
            "cancelledBy",
            Auth.username()
        );
    }

    /**
     * Endpoint that requires ADMIN or MANAGER to view all orders.
     *
     * Demonstrates Guard.anyRole().
     */
    @GetMapping("/orders/all")
    public Map<String, Object> getAllOrders() {
        // Only ADMIN or MANAGER can view all orders
        Guard.anyRole("ADMIN", "MANAGER");

        List<Map<String, Object>> allOrders = new ArrayList<>();
        for (var entry : ordersByUser.entrySet()) {
            for (var order : entry.getValue()) {
                Map<String, Object> orderWithOwner = new HashMap<>(order);
                orderWithOwner.put("ownerId", entry.getKey());
                allOrders.add(orderWithOwner);
            }
        }

        return Map.of(
            "totalOrders",
            allOrders.size(),
            "orders",
            allOrders,
            "requestedBy",
            Auth.username(),
            "userRole",
            Auth.user().getRoles()
        );
    }

    private double calculateTotal(Map<String, Object> orderData) {
        Object priceObj = orderData.get("price");
        Object quantityObj = orderData.getOrDefault("quantity", 1);

        double price =
            priceObj instanceof Number ? ((Number) priceObj).doubleValue() : 0;
        int quantity =
            quantityObj instanceof Number
                ? ((Number) quantityObj).intValue()
                : 1;

        return price * quantity;
    }
}
