package ao.sudojed.lss.demo;

import org.springframework.boot.autoconfigure.SpringBootApplication;

import ao.sudojed.lss.annotation.EnableLazySecurity;
import ao.sudojed.lss.annotation.JwtConfig;

/**
 * Configuração de teste para a Demo Application do LSS.
 * Usada como contexto Spring Boot nos testes de integração.
 */
@SpringBootApplication(scanBasePackages = "ao.sudojed.lss.demo")
@EnableLazySecurity(
    publicPaths = {"/auth/**", "/error"},
    jwt = @JwtConfig(
        secret = "test-secret-key-for-demo-testing-at-least-32-characters-long",
        expiration = 3600000L,        // 1 hora em milissegundos
        refreshExpiration = 604800000L, // 7 dias em milissegundos
        issuer = "lss-demo"
    ),
    corsEnabled = true,
    debug = true
)
public class DemoTestConfig {
}
