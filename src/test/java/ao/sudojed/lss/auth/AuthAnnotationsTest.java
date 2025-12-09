package ao.sudojed.lss.auth;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ao.sudojed.lss.annotation.auth.Login;
import ao.sudojed.lss.annotation.auth.RefreshToken;
import ao.sudojed.lss.annotation.auth.Register;

/**
 * Tests for auth annotations @Login, @Register, @RefreshToken
 */
@DisplayName("Auth Annotations Tests")
class AuthAnnotationsTest {

    @Test
    @DisplayName("@Login annotation should have correct defaults")
    void loginAnnotationDefaults() throws NoSuchMethodException {
        class TestController {
            @Login(userService = Object.class)
            public void login() {}
        }

        Method method = TestController.class.getDeclaredMethod("login");
        Login login = method.getAnnotation(Login.class);

        assertNotNull(login);
        assertEquals("findByUsername", login.findMethod());
        assertEquals("username", login.usernameField());
        assertEquals("passwordHash", login.passwordField());
        assertEquals("roles", login.rolesField());
        assertEquals("id", login.idField());
        assertEquals("username", login.requestUsernameField());
        assertEquals("password", login.requestPasswordField());
        assertEquals("Invalid username or password", login.invalidCredentialsMessage());
        assertFalse(login.includeUserInfo());
        assertEquals(0, login.claims().length);
    }

    @Test
    @DisplayName("@Login annotation should allow custom configuration")
    void loginAnnotationCustomConfig() throws NoSuchMethodException {
        class TestController {
            @Login(
                userService = Object.class,
                findMethod = "findByEmail",
                usernameField = "email",
                passwordField = "senha",
                idField = "uuid",
                rolesField = "permissoes",
                claims = {"email", "nome"},
                requestUsernameField = "email",
                requestPasswordField = "senha",
                includeUserInfo = true,
                invalidCredentialsMessage = "Credenciais inválidas"
            )
            public void login() {}
        }

        Method method = TestController.class.getDeclaredMethod("login");
        Login login = method.getAnnotation(Login.class);

        assertEquals("findByEmail", login.findMethod());
        assertEquals("email", login.usernameField());
        assertEquals("senha", login.passwordField());
        assertEquals("uuid", login.idField());
        assertEquals("permissoes", login.rolesField());
        assertArrayEquals(new String[]{"email", "nome"}, login.claims());
        assertEquals("email", login.requestUsernameField());
        assertEquals("senha", login.requestPasswordField());
        assertTrue(login.includeUserInfo());
        assertEquals("Credenciais inválidas", login.invalidCredentialsMessage());
    }

    @Test
    @DisplayName("@Register annotation should have correct defaults")
    void registerAnnotationDefaults() throws NoSuchMethodException {
        class TestController {
            @Register(userService = Object.class)
            public void register() {}
        }

        Method method = TestController.class.getDeclaredMethod("register");
        Register register = method.getAnnotation(Register.class);

        assertNotNull(register);
        assertEquals("createUser", register.createMethod());
        assertEquals("findByUsername", register.existsMethod());
        assertArrayEquals(new String[]{"username", "email", "password"}, register.requestFields());
        assertEquals("username", register.uniqueField());
        assertFalse(register.autoLogin());
        assertEquals("User already exists", register.existsMessage());
        assertArrayEquals(new String[]{"id", "username"}, register.responseFields());
    }

    @Test
    @DisplayName("@Register annotation should allow custom configuration")
    void registerAnnotationCustomConfig() throws NoSuchMethodException {
        class TestController {
            @Register(
                userService = Object.class,
                createMethod = "criarUsuario",
                existsMethod = "findByEmail",
                requestFields = {"nome", "email", "senha"},
                uniqueField = "email",
                autoLogin = true,
                existsMessage = "Email já cadastrado",
                responseFields = {"id", "nome", "email"}
            )
            public void register() {}
        }

        Method method = TestController.class.getDeclaredMethod("register");
        Register register = method.getAnnotation(Register.class);

        assertEquals("criarUsuario", register.createMethod());
        assertEquals("findByEmail", register.existsMethod());
        assertArrayEquals(new String[]{"nome", "email", "senha"}, register.requestFields());
        assertEquals("email", register.uniqueField());
        assertTrue(register.autoLogin());
        assertEquals("Email já cadastrado", register.existsMessage());
        assertArrayEquals(new String[]{"id", "nome", "email"}, register.responseFields());
    }

    @Test
    @DisplayName("@RefreshToken annotation should have correct defaults")
    void refreshTokenAnnotationDefaults() throws NoSuchMethodException {
        class TestController {
            @RefreshToken
            public void refresh() {}
        }

        Method method = TestController.class.getDeclaredMethod("refresh");
        RefreshToken refreshToken = method.getAnnotation(RefreshToken.class);

        assertNotNull(refreshToken);
        assertEquals("refresh_token", refreshToken.tokenField());
        assertEquals("Invalid or expired refresh token", refreshToken.invalidTokenMessage());
        assertEquals("refresh_token is required", refreshToken.missingTokenMessage());
    }

    @Test
    @DisplayName("@RefreshToken annotation should allow custom configuration")
    void refreshTokenAnnotationCustomConfig() throws NoSuchMethodException {
        class TestController {
            @RefreshToken(
                tokenField = "refreshToken",
                invalidTokenMessage = "Token inválido ou expirado",
                missingTokenMessage = "Token de atualização é obrigatório"
            )
            public void refresh() {}
        }

        Method method = TestController.class.getDeclaredMethod("refresh");
        RefreshToken refreshToken = method.getAnnotation(RefreshToken.class);

        assertEquals("refreshToken", refreshToken.tokenField());
        assertEquals("Token inválido ou expirado", refreshToken.invalidTokenMessage());
        assertEquals("Token de atualização é obrigatório", refreshToken.missingTokenMessage());
    }

    @Test
    @DisplayName("@Login should be meta-annotated with @Public")
    void loginShouldBePublic() {
        assertTrue(Login.class.isAnnotationPresent(ao.sudojed.lss.annotation.Public.class),
            "@Login should be meta-annotated with @Public");
    }

    @Test
    @DisplayName("@Register should be meta-annotated with @Public")
    void registerShouldBePublic() {
        assertTrue(Register.class.isAnnotationPresent(ao.sudojed.lss.annotation.Public.class),
            "@Register should be meta-annotated with @Public");
    }

    @Test
    @DisplayName("@RefreshToken should be meta-annotated with @Public")
    void refreshTokenShouldBePublic() {
        assertTrue(RefreshToken.class.isAnnotationPresent(ao.sudojed.lss.annotation.Public.class),
            "@RefreshToken should be meta-annotated with @Public");
    }
}
