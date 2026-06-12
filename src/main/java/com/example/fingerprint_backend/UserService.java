package com.example.fingerprint_backend;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.Optional;

@Service
public class UserService {

    // spring dependency injection example here : spring automatically gives
    // Userservice a Userrepository
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // user registration
    public boolean register(String username, String password, String name, String email, String phone, String address) {
        if (userRepository.findByUsername(username).isPresent()) {
            return false;
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

    // login validation
    public boolean validateUser(String username, String password) {

        System.out.println("Login attempt:");
        System.out.println("Username entered: " + username);

        Optional<User> user = userRepository.findByUsername(username);

        System.out.println("User found? " + user.isPresent());

        if (user.isPresent()) {
            System.out.println("Stored hash: " + user.get().getPassword());

            boolean matches = passwordEncoder.matches(password, user.get().getPassword());

            System.out.println("Password matches? " + matches);

            return matches;
        }

        return false;
    }
}