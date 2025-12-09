package ao.sudojed.lss.exception;

import org.springframework.http.HttpStatus;

/**
 * Base exception for LazySpringSecurity.
 * All security exceptions extend this class.
 *
 * @author Sudojed Team
 */
public class LazySecurityException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    public LazySecurityException(String message) {
        this(message, HttpStatus.UNAUTHORIZED, "SECURITY_ERROR");
    }

    public LazySecurityException(String message, Throwable cause) {
        this(message, HttpStatus.UNAUTHORIZED, "SECURITY_ERROR", cause);
    }

    public LazySecurityException(String message, HttpStatus status) {
        this(message, status, "SECURITY_ERROR");
    }

    public LazySecurityException(String message, HttpStatus status, String errorCode) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

    public LazySecurityException(String message, HttpStatus status, String errorCode, Throwable cause) {
        super(message, cause);
        this.status = status;
        this.errorCode = errorCode;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
