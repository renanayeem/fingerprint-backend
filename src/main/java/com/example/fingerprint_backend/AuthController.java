package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    private Map<String, String> fingerprintStore = new HashMap<>();

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest request) {
        String username = request.getUsername();
        String password = request.getPassword();
        String fingerprint = request.getFingerprint();

        if ("admin".equals(username) && "admin".equals(password)) {
            fingerprintStore.put(username, fingerprint);
            System.out.println("Login successful! Fingerprint stored for: " + username);
            return ResponseEntity.ok(Map.of("message", "Login successful!"));
        } else {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials!"));
        }
    }

    @GetMapping("/data")
    public ResponseEntity<Map<String, String>> getData(
            @RequestHeader(value = "X-Client-Fingerprint", required = false) String fingerprint) {

        String storedFingerprint = fingerprintStore.get("admin");

        if (storedFingerprint == null || !storedFingerprint.equals(fingerprint)) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid fingerprint!"));
        }

        return ResponseEntity.ok(Map.of("message", "Data fetched successfully!"));
    }

    @PostMapping("/data")
    public ResponseEntity<Map<String, String>> postData(
            @RequestHeader(value = "X-Client-Fingerprint", required = false) String fingerprint) {

        String storedFingerprint = fingerprintStore.get("admin");

        if (storedFingerprint == null || !storedFingerprint.equals(fingerprint)) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid fingerprint!"));
        }

        return ResponseEntity.ok(Map.of("message", "Data posted successfully!"));
    }
}