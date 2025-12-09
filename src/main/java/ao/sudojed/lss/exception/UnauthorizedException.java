package ao.sudojed.lss.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when authentication fails or is missing (401 Unauthorized).
 *
 * @author Sudojed Team
 */
public class UnauthorizedException extends LazySecurityException {

    public UnauthorizedException() {
        this("Authentication required");
    }

    public UnauthorizedException(String message) {
        super(message, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED");
    }

    public UnauthorizedException(String message, Throwable cause) {
        super(message, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", cause);
    }
}
