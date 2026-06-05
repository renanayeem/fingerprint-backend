package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.util.HashMap;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    private Map<String, String> fingerprintStore = new HashMap<>();

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response) {

        String username = request.getUsername();
        String password = request.getPassword();
        String fingerprint = request.getFingerprint();

        if ("admin".equals(username) && "admin".equals(password)) {
            fingerprintStore.put(username, fingerprint);

            Cookie cookie = new Cookie("fingerprint", fingerprint);
            cookie.setHttpOnly(true);
            cookie.setPath("/");
            cookie.setMaxAge(8 * 60 * 60);
            response.addCookie(cookie);

            System.out.println("Login successful! Fingerprint stored and cookie set for: " + username);
            return ResponseEntity.ok(Map.of("message", "Login successful!"));
        } else {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials!"));
        }
    }

    @GetMapping("/data")
    public ResponseEntity<Map<String, String>> getData(
            @CookieValue(value = "fingerprint", required = false) String fingerprint) {

        String storedFingerprint = fingerprintStore.get("admin");

        if (storedFingerprint == null || !storedFingerprint.equals(fingerprint)) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid fingerprint!"));
        }

        return ResponseEntity.ok(Map.of("message", "Data fetched successfully!"));
    }

    @PostMapping("/data")
    public ResponseEntity<Map<String, String>> postData(
            @CookieValue(value = "fingerprint", required = false) String fingerprint) {

        String storedFingerprint = fingerprintStore.get("admin");

        if (storedFingerprint == null || !storedFingerprint.equals(fingerprint)) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid fingerprint!"));
        }

        return ResponseEntity.ok(Map.of("message", "Data posted successfully!"));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("fingerprint", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        fingerprintStore.remove("admin");

        return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
    }
}