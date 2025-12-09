package ao.sudojed.lss.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Password hashing utility.
 * Uses BCrypt by default (OWASP recommended).
 *
 * @author Sudojed Team
 */
public final class PasswordUtils {

    private static final PasswordEncoder encoder = new BCryptPasswordEncoder();

    private PasswordUtils() {
        // Utility class
    }

    /**
     * Generates password hash using BCrypt.
     */
    public static String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    /**
     * Verifies if password matches the hash.
     */
    public static boolean matches(String rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }

    /**
     * Returns the PasswordEncoder for use with Spring Security.
     */
    public static PasswordEncoder encoder() {
        return encoder;
    }
}
