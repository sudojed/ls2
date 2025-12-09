package ao.sudojed.lss.filter;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.method.HandlerMethod;

import ao.sudojed.lss.annotation.RateLimit;
import ao.sudojed.lss.core.LazySecurityContext;
import ao.sudojed.lss.exception.RateLimitExceededException;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Rate limiting manager for LazySpringSecurity.
 * In-memory implementation (for production, consider using Redis).
 *
 * @author Sudojed Team
 */
public class RateLimitManager {

    private static final Logger log = LoggerFactory.getLogger(RateLimitManager.class);

    private final Map<String, RateLimitBucket> buckets = new ConcurrentHashMap<>();

    /**
     * Checks and applies rate limit for a request.
     * 
     * @throws RateLimitExceededException if limit is exceeded
     */
    public void checkRateLimit(HttpServletRequest request, HandlerMethod handler) {
        RateLimit rateLimit = findRateLimitAnnotation(handler);
        
        if (rateLimit == null) {
            return;
        }

        String key = buildKey(request, rateLimit);
        RateLimitBucket bucket = buckets.computeIfAbsent(key, 
                k -> new RateLimitBucket(rateLimit.requests(), rateLimit.window()));

        if (!bucket.tryConsume()) {
            log.warn("Rate limit exceeded for key: {}", key);
            throw new RateLimitExceededException(rateLimit.message(), rateLimit.window());
        }
    }

    private RateLimit findRateLimitAnnotation(HandlerMethod handler) {
        // First check on the method
        RateLimit methodAnnotation = handler.getMethodAnnotation(RateLimit.class);
        if (methodAnnotation != null) {
            return methodAnnotation;
        }

        // Then check on the class
        return handler.getBeanType().getAnnotation(RateLimit.class);
    }

    private String buildKey(HttpServletRequest request, RateLimit rateLimit) {
        String baseKey = request.getMethod() + ":" + request.getRequestURI();
        
        return switch (rateLimit.key()) {
            case "ip" -> baseKey + ":ip:" + getClientIp(request);
            case "user" -> baseKey + ":user:" + LazySecurityContext.getUserId();
            case "token" -> baseKey + ":token:" + request.getHeader("Authorization");
            default -> baseKey + ":" + rateLimit.key();
        };
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }

    /**
     * Cleans up expired buckets (call periodically).
     */
    public void cleanup() {
        long now = System.currentTimeMillis();
        buckets.entrySet().removeIf(entry -> entry.getValue().isExpired(now));
    }

    /**
     * Bucket for rate limit control using fixed window algorithm.
     */
    private static class RateLimitBucket {
        private final int maxRequests;
        private final long windowMillis;
        private final AtomicInteger count = new AtomicInteger(0);
        private final AtomicLong windowStart = new AtomicLong(System.currentTimeMillis());

        RateLimitBucket(int maxRequests, int windowSeconds) {
            this.maxRequests = maxRequests;
            this.windowMillis = windowSeconds * 1000L;
        }

        synchronized boolean tryConsume() {
            long now = System.currentTimeMillis();
            long currentWindowStart = windowStart.get();

            // New window
            if (now - currentWindowStart >= windowMillis) {
                windowStart.set(now);
                count.set(1);
                return true;
            }

            // Same window
            return count.incrementAndGet() <= maxRequests;
        }

        boolean isExpired(long now) {
            return now - windowStart.get() >= windowMillis * 2;
        }
    }
}
