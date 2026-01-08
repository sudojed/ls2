package ao.sudojed.lss.aspect;

import ao.sudojed.lss.annotation.auth.Login;
import ao.sudojed.lss.annotation.auth.RefreshToken;
import ao.sudojed.lss.annotation.auth.Register;
import ao.sudojed.lss.core.LazyUser;
import ao.sudojed.lss.facade.Auth;
import ao.sudojed.lss.jwt.JwtService;
import ao.sudojed.lss.jwt.TokenPair;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Corrected version of AuthEndpointAspect with improved logging and debugging.
 * Fixes the "user already registered" issue by improving existence checking logic.
 */
@Aspect
@Component
public class AuthEndpointAspectFixed {

    private static final Logger log = LoggerFactory.getLogger(AuthEndpointAspectFixed.class);

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private JwtService jwtService;

    // Cache for reflection operations
    private final Map<String, Method> methodCache = new ConcurrentHashMap<>();

    /**
     * Intercepts methods annotated with @Register and handles user registration automatically.
     * CORRECTED VERSION with better logging and debugging.
     */
    @Around("@annotation(register)")
    public Object handleRegister(ProceedingJoinPoint joinPoint, Register register) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        log.info("=== STARTING REGISTRATION PROCESS ===");
        log.info("Processing @Register annotation on method: {}", methodName);

        try {
            // Extract request body
            Object requestBody = extractRequestBody(joinPoint);
            if (requestBody == null) {
                log.error("Request body is null");
                return errorResponse(HttpStatus.BAD_REQUEST, "MISSING_BODY", "Request body is required");
            }
            log.info("Request body extracted successfully: {}", requestBody.getClass().getSimpleName());

            // Get user service
            Object userService = applicationContext.getBean(register.userService());
            log.info("UserService obtained: {}", userService.getClass().getSimpleName());

            // Extract unique field value for existence check
            String uniqueValue = extractField(requestBody, register.uniqueField(), String.class);
            log.info("Unique field '{}' value: '{}'", register.uniqueField(), uniqueValue);

            // Check if user already exists - IMPROVED LOGIC
            if (uniqueValue != null && !uniqueValue.trim().isEmpty() && !register.existsMethod().isEmpty()) {
                log.info("Checking if user exists using method: {}", register.existsMethod());

                try {
                    Optional<?> existing = invokeMethod(userService, register.existsMethod(), uniqueValue);
                    log.info("Existence check result - isPresent: {}", existing.isPresent());

                    if (existing.isPresent()) {
                        Object existingUser = existing.get();
                        log.warn("User already exists! Found: {}", existingUser);
                        String errorMsg = register.existsMessage().replace("{field}", uniqueValue);
                        log.warn("Returning conflict response: {}", errorMsg);
                        return errorResponse(HttpStatus.CONFLICT, "USER_EXISTS", errorMsg);
                    } else {
                        log.info("No existing user found, proceeding with registration");
                    }
                } catch (Exception e) {
                    log.error("Error during existence check: {}", e.getMessage(), e);
                    // Continue with registration if existence check fails - may be a new database
                    log.warn("Continuing with registration despite existence check failure");
                }
            } else {
                log.info("Skipping existence check - unique value empty or no exists method configured");
            }

            // Prepare arguments for user creation
            Object[] createArgs = new Object[register.requestFields().length];
            log.info("Preparing {} arguments for user creation", register.requestFields().length);

            for (int i = 0; i < register.requestFields().length; i++) {
                String fieldName = register.requestFields()[i];
                Object fieldValue = extractField(requestBody, fieldName, Object.class);
                createArgs[i] = fieldValue;
                log.debug("Argument {}: {} = {}", i, fieldName,
                         fieldName.toLowerCase().contains("password") ? "***HIDDEN***" : fieldValue);
            }

            // Create the user
            log.info("Calling user creation method: {}", register.createMethod());
            Object newUser = invokeMethodWithArgs(userService, register.createMethod(), createArgs);
            log.info("User created successfully: {}", newUser != null ? newUser.getClass().getSimpleName() : "null");

            // Build response
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("message", "User created successfully!");
            log.info("Building response with {} fields", register.responseFields().length);

            // Add response fields
            for (String field : register.responseFields()) {
                try {
                    Object value = extractField(newUser, field, Object.class);
                    if (value != null) {
                        response.put(field, value);
                        log.debug("Added response field: {} = {}", field, value);
                    }
                } catch (Exception e) {
                    log.warn("Could not extract response field '{}': {}", field, e.getMessage());
                }
            }

            // Auto-login if requested
            if (register.autoLogin()) {
                log.info("Auto-login enabled, creating tokens");
                try {
                    LazyUser lazyUser = buildLazyUserFromEntity(newUser);
                    TokenPair tokens = jwtService.createTokens(lazyUser);
                    response.putAll(tokens.toMap());
                    log.info("Tokens created and added to response");
                } catch (Exception e) {
                    log.error("Failed to create tokens for auto-login: {}", e.getMessage(), e);
                    // Don't fail the registration, just skip auto-login
                }
            }

            log.info("=== REGISTRATION COMPLETED SUCCESSFULLY ===");
            log.info("Final response keys: {}", response.keySet());
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            log.error("=== REGISTRATION FAILED ===");
            log.error("Error during registration: {}", e.getMessage(), e);

            // Check if it's a user-already-exists exception from the service layer
            if (e.getMessage() != null && e.getMessage().toLowerCase().contains("already exists")) {
                log.warn("User already exists exception from service layer");
                return errorResponse(HttpStatus.CONFLICT, "USER_EXISTS", e.getMessage());
            }

            return errorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "REGISTER_ERROR",
                "An error occurred during registration: " + e.getMessage());
        }
    }

    /**
     * Extract request body from join point arguments.
     */
    private Object extractRequestBody(ProceedingJoinPoint joinPoint) {
        Object[] args = joinPoint.getArgs();
        if (args == null || args.length == 0) {
            return null;
        }

        // Look for @RequestBody parameter or the first non-primitive argument
        for (Object arg : args) {
            if (arg != null && !arg.getClass().isPrimitive() &&
                !arg.getClass().getName().startsWith("java.lang") &&
                !arg.getClass().getName().startsWith("org.springframework")) {
                return arg;
            }
        }
        return null;
    }

    /**
     * Invoke a method with a single string parameter and return Optional result.
     */
    @SuppressWarnings("unchecked")
    private Optional<?> invokeMethod(Object obj, String methodName, String arg) throws Exception {
        log.debug("Invoking method: {}.{}('{}')", obj.getClass().getSimpleName(), methodName, arg);

        Method method = findMethod(obj.getClass(), methodName, String.class);
        if (method == null) {
            throw new IllegalArgumentException(
                "Method " + methodName + "(String) not found in " + obj.getClass().getName());
        }

        Object result = method.invoke(obj, arg);
        log.debug("Method {} returned: {}", methodName, result);

        if (result instanceof Optional) {
            Optional<?> optional = (Optional<?>) result;
            log.debug("Result is Optional, present: {}", optional.isPresent());
            return optional;
        }

        // If method doesn't return Optional, wrap the result
        Optional<?> wrapped = Optional.ofNullable(result);
        log.debug("Wrapped non-Optional result, present: {}", wrapped.isPresent());
        return wrapped;
    }

    /**
     * Invoke a method with multiple arguments.
     */
    private Object invokeMethodWithArgs(Object obj, String methodName, Object[] args) throws Exception {
        log.debug("Invoking method: {}.{}() with {} arguments",
                 obj.getClass().getSimpleName(), methodName, args.length);

        for (Method method : obj.getClass().getMethods()) {
            if (method.getName().equals(methodName) && method.getParameterCount() == args.length) {
                log.debug("Found matching method: {}", method);

                try {
                    Object result = method.invoke(obj, args);
                    log.debug("Method invocation successful");
                    return result;
                } catch (Exception e) {
                    log.error("Method invocation failed: {}", e.getMessage(), e);
                    throw e;
                }
            }
        }

        String error = "Method " + methodName + " with " + args.length + " args not found in " + obj.getClass().getName();
        log.error(error);
        throw new IllegalArgumentException(error);
    }

    /**
     * Find a method by name and parameter types.
     */
    private Method findMethod(Class<?> clazz, String name, Class<?>... paramTypes) {
        String cacheKey = clazz.getName() + "." + name + "(" + Arrays.toString(paramTypes) + ")";

        return methodCache.computeIfAbsent(cacheKey, k -> {
            try {
                return clazz.getMethod(name, paramTypes);
            } catch (NoSuchMethodException e) {
                log.debug("Method not found: {}", cacheKey);
                return null;
            }
        });
    }

    /**
     * Extract field value using reflection or getter methods.
     */
    @SuppressWarnings("unchecked")
    private <T> T extractField(Object obj, String fieldName, Class<T> type) {
        if (obj == null) {
            log.debug("Cannot extract field '{}' from null object", fieldName);
            return null;
        }

        try {
            // Handle Map objects (common for JSON request bodies)
            if (obj instanceof Map<?, ?> map) {
                Object value = map.get(fieldName);
                log.debug("Extracted field '{}' from Map: {}", fieldName, value);
                return type.isInstance(value) ? type.cast(value) : convertToType(value, type);
            }

            // Try getter method first
            String getterName = "get" + capitalize(fieldName);
            try {
                Method getter = obj.getClass().getMethod(getterName);
                Object value = getter.invoke(obj);
                log.debug("Extracted field '{}' via getter {}: {}", fieldName, getterName, value);
                return type.isInstance(value) ? type.cast(value) : convertToType(value, type);
            } catch (NoSuchMethodException e) {
                // Try direct method call (for record classes)
                try {
                    Method method = obj.getClass().getMethod(fieldName);
                    Object value = method.invoke(obj);
                    log.debug("Extracted field '{}' via direct method: {}", fieldName, value);
                    return type.isInstance(value) ? type.cast(value) : convertToType(value, type);
                } catch (NoSuchMethodException e2) {
                    // Try direct field access
                    Field field = obj.getClass().getDeclaredField(fieldName);
                    field.setAccessible(true);
                    Object value = field.get(obj);
                    log.debug("Extracted field '{}' via direct field access: {}", fieldName, value);
                    return type.isInstance(value) ? type.cast(value) : convertToType(value, type);
                }
            }
        } catch (Exception e) {
            log.warn("Could not extract field '{}' from {}: {}",
                    fieldName, obj.getClass().getSimpleName(), e.getMessage());
            return null;
        }
    }

    /**
     * Convert value to target type.
     */
    @SuppressWarnings("unchecked")
    private <T> T convertToType(Object value, Class<T> type) {
        if (value == null) return null;
        if (type.isInstance(value)) return type.cast(value);
        if (type == String.class) return (T) String.valueOf(value);
        return null;
    }

    /**
     * Capitalize first letter of a string.
     */
    private String capitalize(String str) {
        if (str == null || str.isEmpty()) return str;
        return str.substring(0, 1).toUpperCase() + str.substring(1);
    }

    /**
     * Build LazyUser from entity object.
     */
    private LazyUser buildLazyUserFromEntity(Object user) {
        try {
            Object id = extractField(user, "id", Object.class);
            String username = extractField(user, "username", String.class);
            String[] roles = extractRoles(user, "roles");

            return LazyUser.builder()
                .id(String.valueOf(id))
                .username(username)
                .roles(roles)
                .build();
        } catch (Exception e) {
            log.error("Failed to build LazyUser from entity: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to build LazyUser", e);
        }
    }

    /**
     * Extract roles from user entity.
     */
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

        if (rolesObj instanceof String[] array) {
            return array;
        }

        if (rolesObj instanceof String str) {
            return str.split("[,;\\s]+");
        }

        return new String[]{String.valueOf(rolesObj)};
    }

    /**
     * Create error response.
     */
    private ResponseEntity<Map<String, Object>> errorResponse(HttpStatus status, String code, String message) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("error", code);
        error.put("message", message);
        error.put("status", status.value());
        error.put("timestamp", System.currentTimeMillis());

        log.info("Returning error response: {} - {}", code, message);
        return ResponseEntity.status(status).body(error);
    }
}
