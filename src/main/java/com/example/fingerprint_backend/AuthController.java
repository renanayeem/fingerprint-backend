package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    private final SessionRegistry sessionRegistry;
    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final UserRepository userRepository;
    private final VehicleRepository vehicleRepository;

    public AuthController(SessionRegistry sessionRegistry, JwtUtil jwtUtil, UserService userService,
            UserRepository userRepository, VehicleRepository vehicleRepository) {
        this.sessionRegistry = sessionRegistry;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.userRepository = userRepository;
        this.vehicleRepository = vehicleRepository;
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

        // Only store fingerprint if no active session exists.
        // If a session already exists (Browser 1), Browser 2's fingerprint is NOT saved
        // —
        // so Browser 2's subsequent API calls will fail the fingerprint check.
        String existingFingerprint = sessionRegistry.getFingerprint(username);
        if (existingFingerprint == null) {
            sessionRegistry.saveFingerprint(username, fingerprint);
        }

        String token = jwtUtil.generateToken(username);

        Cookie jwtCookie = new Cookie("jwt", token);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(24 * 60 * 60);
        response.addCookie(jwtCookie);

        System.out.println("Login successful for: " + username);
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
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            User u = user.get();
            return ResponseEntity.ok(Map.of(
                    "username", u.getUsername() != null ? u.getUsername() : "",
                    "name", u.getName() != null ? u.getName() : "",
                    "email", u.getEmail() != null ? u.getEmail() : "",
                    "phone", u.getPhone() != null ? u.getPhone() : "",
                    "address", u.getAddress() != null ? u.getAddress() : ""));
        }
        return ResponseEntity.status(404).body(Map.of("message", "User not found"));
    }

    @GetMapping("/vehicles")
    public ResponseEntity<?> getVehicles(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        List<Vehicle> vehicles = vehicleRepository.findByOwnerUsername(username);
        return ResponseEntity.ok(vehicles);
    }

    @PostMapping("/vehicles")
    public ResponseEntity<Map<String, String>> addVehicle(
            @RequestBody VehicleRequest request,
            HttpServletRequest httpRequest) {
        String username = (String) httpRequest.getAttribute("username");
        Vehicle vehicle = new Vehicle();
        vehicle.setOwnerUsername(username);
        vehicle.setVehicleName(request.getVehicleName());
        vehicle.setVehicleNumber(request.getVehicleNumber());
        vehicle.setVehicleType(request.getVehicleType());
        vehicleRepository.save(vehicle);
        return ResponseEntity.ok(Map.of("message", "Vehicle added successfully!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        String username = (String) request.getAttribute("username");
        if (username != null) {
            sessionRegistry.delete(username);
        }

        Cookie jwtCookie = new Cookie("jwt", null);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(0);
        response.addCookie(jwtCookie);

        return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
    }
}