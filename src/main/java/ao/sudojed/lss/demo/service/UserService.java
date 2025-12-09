package ao.sudojed.lss.demo.service;

import ao.sudojed.lss.demo.model.User;
import ao.sudojed.lss.facade.Auth;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * User service for demonstration.
 * Uses in-memory storage (in production would be a JPA repository).
 * 
 * @author Sudojed Team
 */
@Service
public class UserService {

    // Simulates in-memory database
    private final Map<String, User> usersById = new ConcurrentHashMap<>();
    private final Map<String, User> usersByUsername = new ConcurrentHashMap<>();

    public UserService() {
        // Creates demo users
        initializeDemoUsers();
    }

    private void initializeDemoUsers() {
        // Default admin
        User admin = createUser("admin", "admin@example.com", "admin123");
        admin.addRole("ADMIN");
        admin.setDisplayName("Administrator");
        
        // Test users
        User john = createUser("john", "john@example.com", "123456");
        john.setDisplayName("John Doe");
        
        User jane = createUser("jane", "jane@example.com", "123456");
        jane.setDisplayName("Jane Smith");
        jane.addRole("MANAGER");
        
        System.out.println("""
            
            Demo users created:
            ========================================================
              Username  |  Password  |  Roles
            --------------------------------------------------------
              admin     |  admin123  |  USER, ADMIN
              john      |  123456    |  USER
              jane      |  123456    |  USER, MANAGER
            ========================================================
            """);
    }

    /**
     * Creates a new user.
     * Uses Auth.hashPassword() to hash the password.
     */
    public User createUser(String username, String email, String password) {
        String id = "user-" + UUID.randomUUID().toString().substring(0, 8);
        String passwordHash = Auth.hashPassword(password);
        
        User user = new User(id, username, email, passwordHash);
        user.addRole("USER"); // Default role
        
        usersById.put(id, user);
        usersByUsername.put(username, user);
        
        return user;
    }

    /**
     * Finds user by ID.
     */
    public Optional<User> findById(String id) {
        return Optional.ofNullable(usersById.get(id));
    }

    /**
     * Finds user by username.
     */
    public Optional<User> findByUsername(String username) {
        return Optional.ofNullable(usersByUsername.get(username));
    }

    /**
     * Lists all users.
     */
    public List<User> findAll() {
        return new ArrayList<>(usersById.values());
    }

    /**
     * Saves/updates a user.
     */
    public User save(User user) {
        usersById.put(user.getId(), user);
        usersByUsername.put(user.getUsername(), user);
        return user;
    }

    /**
     * Deletes a user by ID.
     */
    public boolean deleteById(String id) {
        User user = usersById.remove(id);
        if (user != null) {
            usersByUsername.remove(user.getUsername());
            return true;
        }
        return false;
    }
}
