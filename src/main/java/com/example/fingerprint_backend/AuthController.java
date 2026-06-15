package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.web.bind.MethodArgumentNotValidException;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;

    public AuthController(AuthService authService, UserService userService) {
        this.authService = authService;
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response) {
        return authService.login(request, response);
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@Valid @RequestBody LoginRequest request) {
        try {
            boolean success = userService.register(
                    request.getUsername(),
                    request.getPassword(),
                    request.getName(),
                    request.getEmail(),
                    request.getPhone(),
                    request.getAddress());
            if (success) {
                return ResponseEntity.ok(Map.of("message", "Registration successful!"));
            } else {
                return ResponseEntity.status(400).body(Map.of("message", "Username already exists!"));
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body(Map.of("message", e.getMessage()));
        }
    }

    @GetMapping("/secure")
    public ResponseEntity<Map<String, String>> secureEndpoint(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        return ResponseEntity.ok(Map.of("message", "Secure endpoint accessed by: " + username));
    }

    @GetMapping("/data")
    public ResponseEntity<Map<String, String>> getData() {
        return ResponseEntity.ok(Map.of("message", "Data fetched successfully!"));
    }

    @PostMapping("/data")
    public ResponseEntity<Map<String, String>> postData() {
        return ResponseEntity.ok(Map.of("message", "Data posted successfully!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        return authService.logout(request, response);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationErrors(MethodArgumentNotValidException ex) {
        String errorMessage = ex.getBindingResult().getFieldErrors().stream()
                .map(error -> error.getDefaultMessage())
                .findFirst()
                .orElse("Validation failed!");
        return ResponseEntity.status(400).body(Map.of("message", errorMessage));
    }
}