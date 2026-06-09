package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    private final SessionRegistry sessionRegistry;
    private final JwtUtil jwtUtil;

    public AuthController(SessionRegistry sessionRegistry, JwtUtil jwtUtil) {
        this.sessionRegistry = sessionRegistry;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response) {

        String username = request.getUsername();
        String password = request.getPassword();
        String fingerprint = request.getFingerprint();

        if ("admin".equals(username) && "admin".equals(password)) {
            sessionRegistry.saveFingerprint(username, fingerprint);

            Cookie cookie = new Cookie("fingerprint", fingerprint);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(8 * 60 * 60);
            response.addCookie(cookie);

            String token = jwtUtil.generateToken(username);

            System.out.println("Login successful! Fingerprint stored in Redis for: " + username);
            return ResponseEntity.ok(Map.of("message", "Login successful!", "token", token));
        } else {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials!"));
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
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response) {
        sessionRegistry.delete("admin");

        Cookie cookie = new Cookie("fingerprint", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
    }
}