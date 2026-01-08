package ao.sudojed.lss.config;

import ao.sudojed.lss.annotation.Public;
import jakarta.annotation.PostConstruct;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * Primary endpoint security scanner for LazySpringSecurity.
 *
 * This component is the SOURCE OF TRUTH for endpoint security configuration.
 * It automatically discovers and categorizes all endpoints based on annotations:
 *
 * <h2>Public Endpoints</h2>
 * <ul>
 *   <li>Methods annotated with @Public</li>
 *   <li>Classes annotated with @Public (all methods become public)</li>
 *   <li>Methods with meta-annotations containing @Public (@Register, @Login, @RefreshToken)</li>
 * </ul>
 *
 * <h2>Protected Endpoints</h2>
 * <ul>
 *   <li>Methods annotated with @Secured</li>
 *   <li>Methods with role-specific @Secured("ROLE")</li>
 *   <li>All other controller methods (default: require authentication)</li>
 * </ul>
 *
 * <h2>Benefits</h2>
 * <ul>
 *   <li>Eliminates need for manual publicPaths configuration</li>
 *   <li>Annotation-driven security (source of truth in code)</li>
 *   <li>Automatic Spring Security configuration</li>
 *   <li>Runtime endpoint discovery and validation</li>
 * </ul>
 *
 * @author LSS Team
 * @since 1.0.1
 */
@Component
public class PublicEndpointScanner {

    private static final Logger log = LoggerFactory.getLogger(
        PublicEndpointScanner.class
    );

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private RequestMappingHandlerMapping handlerMapping;

    private final Set<String> publicPatterns = new LinkedHashSet<>();
    private final Set<String> protectedPatterns = new LinkedHashSet<>();
    private final Set<String> allEndpointPatterns = new LinkedHashSet<>();
    private boolean scanned = false;

    /**
     * Scan for all endpoint annotations after application context is ready.
     * This becomes the primary source of truth for endpoint security.
     */
    @PostConstruct
    public void scanAllEndpoints() {
        if (scanned) {
            return;
        }

        log.info(
            "Scanning all endpoints for security annotations (@Public, @Secured)..."
        );

        try {
            // Get all request mappings
            Map<RequestMappingInfo, HandlerMethod> handlerMethods =
                handlerMapping.getHandlerMethods();

            int publicCount = 0;
            int protectedCount = 0;

            for (Map.Entry<
                RequestMappingInfo,
                HandlerMethod
            > entry : handlerMethods.entrySet()) {
                RequestMappingInfo mappingInfo = entry.getKey();
                HandlerMethod handlerMethod = entry.getValue();

                Set<String> patterns = extractPatterns(mappingInfo);
                allEndpointPatterns.addAll(patterns);

                if (isPublicEndpoint(handlerMethod)) {
                    publicPatterns.addAll(patterns);
                    publicCount++;
                    log.debug(
                        "Found @Public endpoint: {} -> {}",
                        handlerMethod.getMethod().getName(),
                        patterns
                    );
                } else {
                    protectedPatterns.addAll(patterns);
                    protectedCount++;
                    log.debug(
                        "Found @Secured endpoint: {} -> {}",
                        handlerMethod.getMethod().getName(),
                        patterns
                    );
                }
            }

            log.info("Endpoint security scan completed:");
            log.info(
                "  📂 Total endpoints discovered: {}",
                handlerMethods.size()
            );
            log.info("  🌍 Public endpoints (@Public): {}", publicCount);
            log.info(
                "  🔒 Protected endpoints (@Secured/default): {}",
                protectedCount
            );

            scanned = true;

            if (publicCount > 0) {
                log.info("🌍 Public patterns: {}", publicPatterns);
            }
            if (protectedCount > 0 && log.isDebugEnabled()) {
                log.debug("🔒 Protected patterns: {}", protectedPatterns);
            }
        } catch (Exception e) {
            log.error(
                "Error scanning endpoints for security annotations: {}",
                e.getMessage(),
                e
            );
        }
    }

    /**
     * Get all discovered public patterns.
     */
    public Set<String> getPublicPatterns() {
        if (!scanned) {
            scanAllEndpoints();
        }
        return new LinkedHashSet<>(publicPatterns);
    }

    /**
     * Get all discovered protected patterns.
     */
    public Set<String> getProtectedPatterns() {
        if (!scanned) {
            scanAllEndpoints();
        }
        return new LinkedHashSet<>(protectedPatterns);
    }

    /**
     * Get all endpoint patterns (public + protected).
     */
    public Set<String> getAllEndpointPatterns() {
        if (!scanned) {
            scanAllEndpoints();
        }
        return new LinkedHashSet<>(allEndpointPatterns);
    }

    /**
     * Check if a handler method should be public.
     */
    private boolean isPublicEndpoint(HandlerMethod handlerMethod) {
        Method method = handlerMethod.getMethod();
        Class<?> controllerClass = handlerMethod.getBeanType();

        // Check if method has @Public annotation
        if (method.isAnnotationPresent(Public.class)) {
            log.debug("Method {} has @Public annotation", method.getName());
            return true;
        }

        // Check if class has @Public annotation
        if (controllerClass.isAnnotationPresent(Public.class)) {
            log.debug(
                "Class {} has @Public annotation",
                controllerClass.getSimpleName()
            );
            return true;
        }

        // Check meta-annotations (like @Register, @Login, @RefreshToken)
        if (hasPublicMetaAnnotation(method)) {
            log.debug(
                "Method {} has meta-annotation with @Public",
                method.getName()
            );
            return true;
        }

        return false;
    }

    /**
     * Check if method has any annotation that is meta-annotated with @Public.
     */
    private boolean hasPublicMetaAnnotation(Method method) {
        for (Annotation annotation : method.getAnnotations()) {
            Class<? extends Annotation> annotationType =
                annotation.annotationType();

            // Check if this annotation is meta-annotated with @Public
            if (annotationType.isAnnotationPresent(Public.class)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract URL patterns from RequestMappingInfo.
     */
    private Set<String> extractPatterns(RequestMappingInfo mappingInfo) {
        Set<String> patterns = new LinkedHashSet<>();

        // Get path patterns
        Set<String> pathPatterns = mappingInfo.getDirectPaths();
        if (pathPatterns.isEmpty()) {
            // Fallback for older Spring versions
            pathPatterns =
                mappingInfo.getPatternsCondition() != null
                    ? mappingInfo.getPatternsCondition().getPatterns()
                    : Collections.emptySet();
        }

        if (pathPatterns.isEmpty()) {
            log.warn("No path patterns found for mapping: {}", mappingInfo);
            return patterns;
        }

        // Add all path patterns
        for (String pattern : pathPatterns) {
            patterns.add(pattern);

            // Also add pattern with /** suffix for sub-paths if it doesn't end with *
            if (!pattern.endsWith("*") && !pattern.endsWith("**")) {
                // Add exact pattern first, then wildcard pattern
                if (!pattern.endsWith("/")) {
                    patterns.add(pattern + "/**");
                } else {
                    patterns.add(pattern + "**");
                }
            }
        }

        return patterns;
    }

    /**
     * Add additional public patterns programmatically.
     */
    public void addPublicPattern(String pattern) {
        publicPatterns.add(pattern);
        log.debug("Added public pattern: {}", pattern);
    }

    /**
     * Remove a public pattern.
     */
    public void removePublicPattern(String pattern) {
        publicPatterns.remove(pattern);
        log.debug("Removed public pattern: {}", pattern);
    }

    /**
     * Check if a path should be public based on discovered patterns.
     */
    public boolean isPublicPath(String path) {
        return publicPatterns
            .stream()
            .anyMatch(pattern -> pathMatches(path, pattern));
    }

    /**
     * Simple path matching logic (supports * and ** wildcards).
     */
    private boolean pathMatches(String path, String pattern) {
        if (pattern.equals(path)) {
            return true;
        }

        if (pattern.endsWith("/**")) {
            String prefix = pattern.substring(0, pattern.length() - 3);
            return path.startsWith(prefix);
        }

        if (pattern.endsWith("/*")) {
            String prefix = pattern.substring(0, pattern.length() - 2);
            return (
                path.startsWith(prefix) &&
                path.indexOf('/', prefix.length() + 1) == -1
            );
        }

        if (pattern.contains("*")) {
            // Convert pattern to regex
            String regex = pattern.replace(".", "\\.").replace("*", ".*");
            return path.matches(regex);
        }

        return false;
    }

    /**
     * Get debug information about discovered endpoints.
     */
    public Map<String, Object> getDebugInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("scanned", scanned);
        info.put("totalEndpoints", allEndpointPatterns.size());
        info.put("publicPatternsCount", publicPatterns.size());
        info.put("protectedPatternsCount", protectedPatterns.size());
        info.put("publicPatterns", new ArrayList<>(publicPatterns));
        info.put("protectedPatterns", new ArrayList<>(protectedPatterns));
        info.put("allPatterns", new ArrayList<>(allEndpointPatterns));
        return info;
    }

    /**
     * Check if publicPaths configuration is needed.
     * Returns true if there are patterns not covered by annotations.
     */
    public boolean isLegacyConfigNeeded(Set<String> configuredPublicPaths) {
        if (!scanned) {
            scanAllEndpoints();
        }

        // If no configured paths, no legacy config needed
        if (configuredPublicPaths.isEmpty()) {
            return false;
        }

        // Check if configured paths are already covered by annotations
        for (String configuredPath : configuredPublicPaths) {
            boolean covered = publicPatterns
                .stream()
                .anyMatch(
                    pattern ->
                        pathMatches(configuredPath, pattern) ||
                        pathMatches(pattern, configuredPath)
                );
            if (!covered) {
                log.info(
                    "Legacy publicPath '{}' not covered by @Public annotations",
                    configuredPath
                );
                return true;
            }
        }

        log.info(
            "All publicPaths are covered by @Public annotations - consider removing publicPaths configuration"
        );
        return false;
    }

    /**
     * Force rescan (useful for testing or dynamic updates).
     */
    public void rescan() {
        publicPatterns.clear();
        protectedPatterns.clear();
        allEndpointPatterns.clear();
        scanned = false;
        scanAllEndpoints();
    }
}
