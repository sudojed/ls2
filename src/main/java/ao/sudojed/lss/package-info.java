/**
 * LazySpringSecurity (LSS) - A lightweight, annotation-driven security framework.
 *
 * <h2>Quick Start</h2>
 * <pre>{@code
 * @EnableLazySecurity(
 *     jwt = @JwtConfig(secret = "${app.jwt.secret}"),
 *     publicPaths = {"/api/public/**", "/health"}
 * )
 * @SpringBootApplication
 * public class MyApplication { }
 * }</pre>
 *
 * <h2>Secure Endpoints</h2>
 * <pre>{@code
 * // Any authenticated user
 * @Secured
 * @GetMapping("/profile")
 * public User getProfile() { }
 *
 * // Specific role required
 * @Secured("ADMIN")
 * @GetMapping("/admin/dashboard")
 * public Dashboard getDashboard() { }
 *
 * // Multiple roles (any of them)
 * @Secured({"ADMIN", "MANAGER"})
 * @GetMapping("/reports")
 * public List<Report> getReports() { }
 *
 * // All roles required
 * @Secured(value = {"VERIFIED", "PREMIUM"}, all = true)
 * @GetMapping("/premium-content")
 * public Content getPremiumContent() { }
 *
 * // Public endpoint
 * @Public
 * @PostMapping("/login")
 * public Token login() { }
 * }</pre>
 *
 * @author Sudojed Team
 * @version 1.1.0
 */
package ao.sudojed.lss;
