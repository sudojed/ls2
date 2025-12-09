package ao.sudojed.lss.aspect;

import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import ao.sudojed.lss.annotation.auth.Login;
import ao.sudojed.lss.annotation.auth.RefreshToken;
import ao.sudojed.lss.annotation.auth.Register;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.facade.Auth;
import ao.sudojed.lss.jwt.JwtService;
import ao.sudojed.lss.jwt.TokenPair;

/**
 * Aspect that intercepts methods annotated with @Login, @Register, and @RefreshToken.
 * Automatically handles authentication logic without requiring manual implementation.
 *
 * @author Sudojed Team
 * @since 1.0.0
 */
@Aspect
@Order(50)
public class AuthEndpointAspect {

    private static final Logger log = LoggerFactory.getLogger(AuthEndpointAspect.class);

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private JwtService jwtService;

    /**
     * Intercepts methods annotated with @Login and handles authentication automatically.
     */
    @Around("@annotation(login)")
    public Object handleLogin(ProceedingJoinPoint joinPoint, Login login) throws Throwable {
        log.debug("Processing @Login annotation on method: {}", joinPoint.getSignature().getName());

        try {
            Object requestBody = extractRequestBody(joinPoint);
            if (requestBody == null) {
                return errorResponse(HttpStatus.BAD_REQUEST, "MISSING_BODY", "Request body is required");
            }

            String username = extractField(requestBody, login.requestUsernameField(), String.class);
            String password = extractField(requestBody, login.requestPasswordField(), String.class);

            if (username == null || username.isBlank()) {
                return errorResponse(HttpStatus.BAD_REQUEST, "MISSING_USERNAME", 
                    login.requestUsernameField() + " is required");
            }
            if (password == null || password.isBlank()) {
                return errorResponse(HttpStatus.BAD_REQUEST, "MISSING_PASSWORD", 
                    login.requestPasswordField() + " is required");
            }

            Object userService = applicationContext.getBean(login.userService());
            Optional<?> userOptional = invokeMethod(userService, login.findMethod(), username);
            
            if (userOptional.isEmpty()) {
                return errorResponse(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", 
                    login.invalidCredentialsMessage());
            }

            Object user = userOptional.get();
            String passwordHash = extractField(user, login.passwordField(), String.class);

            if (!Auth.checkPassword(password, passwordHash)) {
                return errorResponse(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS", 
                    login.invalidCredentialsMessage());
            }

            LazyUser lazyUser = buildLazyUser(user, login);
            TokenPair tokens = jwtService.createTokens(lazyUser);

            log.info("Login successful for user: {}", username);

            Map<String, Object> response = new LinkedHashMap<>(tokens.toMap());
            
            if (login.includeUserInfo()) {
                Map<String, Object> userInfo = new LinkedHashMap<>();
                userInfo.put("id", lazyUser.getId());
                userInfo.put("username", lazyUser.getUsername());
                userInfo.put("roles", lazyUser.getRoles());
                response.put("user", userInfo);
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            log.error("Login failed: {}", e.getMessage(), e);
            return errorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "LOGIN_ERROR", 
                "An error occurred during login");
        }
    }

    /**
     * Intercepts methods annotated with @Register and handles user registration automatically.
     * 
     */

    @Around("@annotation(register)")
    public Object handleRegister(ProceedingJoinPoint joinPoint, Register register) throws Throwable {
        log.debug("Processing @Register annotation on method: {}", joinPoint.getSignature().getName());

        try {
            Object requestBody = extractRequestBody(joinPoint);
            if (requestBody == null) {
                return errorResponse(HttpStatus.BAD_REQUEST, "MISSING_BODY", "Request body is required");
            }

            Object userService = applicationContext.getBean(register.userService());

            String uniqueValue = extractField(requestBody, register.uniqueField(), String.class);
            if (uniqueValue != null && !register.existsMethod().isEmpty()) {
                Optional<?> existing = invokeMethod(userService, register.existsMethod(), uniqueValue);
                if (existing.isPresent()) {
                    return errorResponse(HttpStatus.CONFLICT, "USER_EXISTS", 
                        register.existsMessage().replace("{field}", uniqueValue));
                }
            }

            Object[] createArgs = new Object[register.requestFields().length];
            for (int i = 0; i < register.requestFields().length; i++) {
                createArgs[i] = extractField(requestBody, register.requestFields()[i], Object.class);
            }

            Object newUser = invokeMethodWithArgs(userService, register.createMethod(), createArgs);

            log.info("Registration successful for: {}", uniqueValue);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("message", "User created successfully!");

            for (String field : register.responseFields()) {
                Object value = extractField(newUser, field, Object.class);
                if (value != null) {
                    response.put(field, value);
                }
            }

            if (register.autoLogin()) {
                LazyUser lazyUser = buildLazyUserFromEntity(newUser);
                TokenPair tokens = jwtService.createTokens(lazyUser);
                response.putAll(tokens.toMap());
            }

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            log.error("Registration failed: {}", e.getMessage(), e);
            return errorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "REGISTER_ERROR", 
                "An error occurred during registration");
        }
    }

    /**
     * Intercepts methods annotated with @RefreshToken and handles token refresh automatically.
     */
    @Around("@annotation(refreshToken)")
    public Object handleRefreshToken(ProceedingJoinPoint joinPoint, RefreshToken refreshToken) throws Throwable {
        log.debug("Processing @RefreshToken annotation on method: {}", joinPoint.getSignature().getName());

        try {
            Object requestBody = extractRequestBody(joinPoint);
            if (requestBody == null) {
                return errorResponse(HttpStatus.BAD_REQUEST, "MISSING_BODY", "Request body is required");
            }

            String token = extractField(requestBody, refreshToken.tokenField(), String.class);

            if (token == null || token.isBlank()) {
                return errorResponse(HttpStatus.BAD_REQUEST, "MISSING_TOKEN", 
                    refreshToken.missingTokenMessage());
            }

            TokenPair newTokens = jwtService.refresh(token);
            log.debug("Token refresh successful");

            return ResponseEntity.ok(newTokens.toMap());

        } catch (Exception e) {
            log.warn("Token refresh failed: {}", e.getMessage());
            return errorResponse(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN", 
                refreshToken.invalidTokenMessage());
        }
    }

    // ========================================================================
    // HELPER METHODS
    // ========================================================================

    private Object extractRequestBody(ProceedingJoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        if (args == null || args.length == 0) {
            return null;
        }
        
        for (Object arg : args) {
            if (arg != null && !isPrimitiveOrWrapper(arg.getClass())) {
                return arg;
            }
        }
        
        return (args[0] instanceof Map) ? args[0] : null;
    }

    @SuppressWarnings("unchecked")
    private <T> T extractField(Object obj, String fieldName, Class<T> type) {
        if (obj == null) return null;

        try {
            if (obj instanceof Map<?, ?> map) {
                Object value = map.get(fieldName);
                return type.isInstance(value) ? type.cast(value) : null;
            }

            String getterName = "get" + capitalize(fieldName);
            try {
                Method getter = obj.getClass().getMethod(getterName);
                Object value = getter.invoke(obj);
                return type.isInstance(value) ? type.cast(value) : convertToType(value, type);
            } catch (NoSuchMethodException e) {
                try {
                    Method method = obj.getClass().getMethod(fieldName);
                    Object value = method.invoke(obj);
                    return type.isInstance(value) ? type.cast(value) : convertToType(value, type);
                } catch (NoSuchMethodException e2) {
                    Field field = obj.getClass().getDeclaredField(fieldName);
                    field.setAccessible(true);
                    Object value = field.get(obj);
                    return type.isInstance(value) ? type.cast(value) : convertToType(value, type);
                }
            }
        } catch (Exception e) {
            log.trace("Could not extract field '{}' from {}: {}", fieldName, obj.getClass().getSimpleName(), e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private <T> T convertToType(Object value, Class<T> type) {
        if (value == null) return null;
        if (type == Object.class) return (T) value;
        if (type.isInstance(value)) return type.cast(value);
        if (type == String.class) return (T) String.valueOf(value);
        return null;
    }

    @SuppressWarnings("unchecked")
    private Optional<?> invokeMethod(Object obj, String methodName, String arg) throws Exception {
        Method method = findMethod(obj.getClass(), methodName, String.class);
        if (method == null) {
            throw new IllegalArgumentException("Method " + methodName + "(String) not found in " + obj.getClass().getName());
        }
        Object result = method.invoke(obj, arg);
        
        if (result instanceof Optional) {
            return (Optional<?>) result;
        }
        return Optional.ofNullable(result);
    }

    private Object invokeMethodWithArgs(Object obj, String methodName, Object[] args) throws Exception {
        for (Method method : obj.getClass().getMethods()) {
            if (method.getName().equals(methodName) && method.getParameterCount() == args.length) {
                return method.invoke(obj, args);
            }
        }
        throw new IllegalArgumentException("Method " + methodName + " with " + args.length + " args not found in " + obj.getClass().getName());
    }

    private Method findMethod(Class<?> clazz, String name, Class<?>... paramTypes) {
        try {
            return clazz.getMethod(name, paramTypes);
        } catch (NoSuchMethodException e) {
            return null;
        }
    }

    private LazyUser buildLazyUser(Object user, Login login) {
        String id = String.valueOf(extractField(user, login.idField(), Object.class));
        String username = extractField(user, login.usernameField(), String.class);
        String[] roles = extractRoles(user, login.rolesField());

        LazyUser.Builder builder = LazyUser.builder()
            .id(id)
            .username(username)
            .roles(roles);

        for (String claimField : login.claims()) {
            Object value = extractField(user, claimField, Object.class);
            if (value != null) {
                builder.claim(claimField, value);
            }
        }

        return builder.build();
    }

    private LazyUser buildLazyUserFromEntity(Object user) {
        Object id = extractField(user, "id", Object.class);
        String username = extractField(user, "username", String.class);
        String[] roles = extractRoles(user, "roles");

        return LazyUser.builder()
            .id(String.valueOf(id))
            .username(username)
            .roles(roles)
            .build();
    }

    @SuppressWarnings("unchecked")
    private String[] extractRoles(Object user, String rolesField) {
        Object rolesObj = extractField(user, rolesField, Object.class);
        
        if (rolesObj == null) {
            return new String[]{"USER"};
        }
        
        if (rolesObj instanceof Collection<?> collection) {
            return collection.stream()
                .map(String::valueOf)
                .toArray(String[]::new);
        }
        
        if (rolesObj.getClass().isArray()) {
            int length = Array.getLength(rolesObj);
            String[] result = new String[length];
            for (int i = 0; i < length; i++) {
                result[i] = String.valueOf(Array.get(rolesObj, i));
            }
            return result;
        }
        
        return new String[]{String.valueOf(rolesObj)};
    }

    private ResponseEntity<Map<String, Object>> errorResponse(HttpStatus status, String error, String message) {
        return ResponseEntity
            .status(status)
            .body(Map.of(
                "error", error,
                "message", message
            ));
    }

    private boolean isPrimitiveOrWrapper(Class<?> clazz) {
        return clazz.isPrimitive() ||
               clazz == Boolean.class ||
               clazz == Byte.class ||
               clazz == Character.class ||
               clazz == Short.class ||
               clazz == Integer.class ||
               clazz == Long.class ||
               clazz == Float.class ||
               clazz == Double.class ||
               clazz == String.class;
    }

    private String capitalize(String str) {
        if (str == null || str.isEmpty()) return str;
        return Character.toUpperCase(str.charAt(0)) + str.substring(1);
    }
}
