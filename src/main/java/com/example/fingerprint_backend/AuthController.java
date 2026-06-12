package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final SessionRegistry sessionRegistry;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final VehicleService vehicleService;

    public AuthController(SessionRegistry sessionRegistry, JwtUtil jwtUtil, UserService userService,
            VehicleService vehicleService) {
        this.sessionRegistry = sessionRegistry;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.vehicleService = vehicleService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response) {

        String username = request.getUsername();
        String password = request.getPassword();
        String fingerprint = request.getFingerprint();

        if (!userService.validateUser(username, password)) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials!"));
        }

        String existingFingerprint = sessionRegistry.getFingerprint(username);
        log.info("Existing fingerprint in Redis: {}", existingFingerprint != null ? "found" : "not found");

        if (existingFingerprint == null) {
            sessionRegistry.saveFingerprint(username, fingerprint);
            log.info("Saved new fingerprint for: {}", username);
        } else {
            log.info("Session already exists, not overwriting for: {}", username);
        }

        String token = jwtUtil.generateToken(username);
        response.setHeader("Set-Cookie", "jwt=" + token + "; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict");

        log.info("Login successful for: {}", username);
        return ResponseEntity.ok(Map.of("message", "Login successful!"));
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody LoginRequest request) {
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
    }

    @GetMapping("/data")
    public ResponseEntity<Map<String, String>> getData() {
        return ResponseEntity.ok(Map.of("message", "Data fetched successfully!"));
    }

    @PostMapping("/data")
    public ResponseEntity<Map<String, String>> postData() {
        return ResponseEntity.ok(Map.of("message", "Data posted successfully!"));
    }

    @GetMapping("/secure")
    public ResponseEntity<Map<String, String>> secureEndpoint(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        return ResponseEntity.ok(Map.of("message", "Secure endpoint accessed by: " + username));
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        Optional<Map<String, String>> profile = userService.getProfile(username);
        if (profile.isPresent()) {
            return ResponseEntity.ok(profile.get());
        }
        return ResponseEntity.status(404).body(Map.of("message", "User not found"));
    }

    @GetMapping("/vehicles")
    public ResponseEntity<?> getVehicles(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        List<Vehicle> vehicles = vehicleService.getVehicles(username);
        return ResponseEntity.ok(vehicles);
    }

    @PostMapping("/vehicles")
    public ResponseEntity<Map<String, String>> addVehicle(
            @RequestBody VehicleRequest request,
            HttpServletRequest httpRequest) {
        String username = (String) httpRequest.getAttribute("username");
        vehicleService.addVehicle(username, request);
        return ResponseEntity.ok(Map.of("message", "Vehicle added successfully!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        String username = (String) request.getAttribute("username");
        String incomingFingerprint = request.getHeader("X-Client-Fingerprint");

        if (username != null) {
            String storedFingerprint = sessionRegistry.getFingerprint(username);
            if (storedFingerprint != null && storedFingerprint.equals(incomingFingerprint)) {
                sessionRegistry.delete(username);
                log.info("Session deleted for: {}", username);
            } else {
                log.warn("Logout blocked - fingerprint mismatch for: {}", username);
            }
        }

        response.setHeader("Set-Cookie", "jwt=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict");
        return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
    }
}