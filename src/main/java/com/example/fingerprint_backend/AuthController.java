package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;
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

    public AuthController(SessionRegistry sessionRegistry, JwtUtil jwtUtil, UserService userService) {
        this.sessionRegistry = sessionRegistry;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response) {

        String username = request.getUsername();
        String password = request.getPassword();
        String fingerprint = request.getFingerprint();

        if (userService.validateUser(username, password)) {
            sessionRegistry.saveFingerprint(username, fingerprint);

            Cookie fingerprintCookie = new Cookie("fingerprint", fingerprint);
            fingerprintCookie.setHttpOnly(true);
            fingerprintCookie.setPath("/");
            fingerprintCookie.setMaxAge(8 * 60 * 60);
            response.addCookie(fingerprintCookie);

            String token = jwtUtil.generateToken(username);

            Cookie jwtCookie = new Cookie("jwt", token);
            jwtCookie.setHttpOnly(true);
            jwtCookie.setPath("/");
            jwtCookie.setMaxAge(24 * 60 * 60);
            response.addCookie(jwtCookie);

            System.out.println("Login successful for: " + username);
            return ResponseEntity.ok(Map.of("message", "Login successful!"));
        } else {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials!"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody LoginRequest request) {
        boolean success = userService.register(request.getUsername(), request.getPassword());
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

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        String username = (String) request.getAttribute("username");
        if (username != null) {
            sessionRegistry.delete(username);
        }

        Cookie fingerprintCookie = new Cookie("fingerprint", null);
        fingerprintCookie.setHttpOnly(true);
        fingerprintCookie.setPath("/");
        fingerprintCookie.setMaxAge(0);
        response.addCookie(fingerprintCookie);

        Cookie jwtCookie = new Cookie("jwt", null);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setPath("/");
        jwtCookie.setMaxAge(0);
        response.addCookie(jwtCookie);

        return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
    }
}