package ao.sudojed.lss.aspect;

import java.lang.reflect.Method;

import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.annotation.Order;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.HandlerMethod;

import ao.sudojed.lss.filter.RateLimitManager;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Aspect for applying rate limiting to methods annotated with @RateLimit.
 *
 * @author Sudojed Team
 */
@Aspect
@Order(50) // Executes before LazySecurityAspect
public class RateLimitAspect {

    private final RateLimitManager rateLimitManager;

    public RateLimitAspect(RateLimitManager rateLimitManager) {
        this.rateLimitManager = rateLimitManager;
    }

    @Before("@annotation(ao.sudojed.lss.annotation.RateLimit) || @within(ao.sudojed.lss.annotation.RateLimit)")
    public void checkRateLimit(JoinPoint joinPoint) {
        ServletRequestAttributes attributes = 
                (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
        
        if (attributes == null) {
            return;
        }

        HttpServletRequest request = attributes.getRequest();
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Create a fake HandlerMethod for RateLimitManager
        HandlerMethod handlerMethod = new HandlerMethod(joinPoint.getTarget(), method);
        
        rateLimitManager.checkRateLimit(request, handlerMethod);
    }
}
