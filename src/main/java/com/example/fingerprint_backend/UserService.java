package com.example.fingerprint_backend;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {

    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean register(String username, String password, String name, String email, String phone, String address) {

        if (username == null || username.isEmpty()) {
            throw new IllegalArgumentException("Username is required!");
        }

        if (password == null || password.isEmpty()) {
            throw new IllegalArgumentException("Password is required!");
        }

        if (userRepository.findByUsername(username).isPresent()) {
            return false;
        }

        if (email != null && !email.isEmpty() && userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException("Email already exists!");
        }

        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setName(name);
        user.setEmail(email);
        user.setPhone(phone);
        user.setAddress(address);
        userRepository.save(user);
        return true;
    }

    public boolean validateUser(String username, String password) {
        log.info("Login attempt for username: {}", username);
        Optional<User> user = userRepository.findByUsername(username);
        log.info("User found: {}", user.isPresent());
        if (user.isPresent()) {
            boolean matches = passwordEncoder.matches(password, user.get().getPassword());
            log.info("Password matches: {}", matches);
            return matches;
        }
        return false;
    }

    public Optional<Map<String, String>> getProfile(String username) {
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            User u = user.get();
            return Optional.of(Map.of(
                    "username", u.getUsername() != null ? u.getUsername() : "",
                    "name", u.getName() != null ? u.getName() : "",
                    "email", u.getEmail() != null ? u.getEmail() : "",
                    "phone", u.getPhone() != null ? u.getPhone() : "",
                    "address", u.getAddress() != null ? u.getAddress() : ""));
        }
        return Optional.empty();
    }
}