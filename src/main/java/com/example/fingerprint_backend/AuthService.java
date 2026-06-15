package com.example.fingerprint_backend;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final SessionRegistry sessionRegistry;
    private final JwtUtil jwtUtil;
    private final UserService userService;

    public AuthService(SessionRegistry sessionRegistry, JwtUtil jwtUtil, UserService userService) {
        this.sessionRegistry = sessionRegistry;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
    }

    public ResponseEntity<Map<String, String>> login(LoginRequest request, HttpServletResponse response) {
        String username = request.getUsername();
        String password = request.getPassword();
        String fingerprint = request.getFingerprint();

        if (fingerprint == null || fingerprint.isEmpty()) {
            log.warn("Login rejected - null or empty fingerprint for: {}", username);
            return ResponseEntity.status(400).body(Map.of("message", "Fingerprint is required!"));
        }

        if (!userService.validateUser(username, password)) {
            return ResponseEntity.status(401).body(Map.of("message", "Invalid credentials!"));
        }

        boolean saved = sessionRegistry.saveFingerprintIfAbsent(username, fingerprint);

        if (!saved) {
            log.info("Session already exists for: {}", username);
            return ResponseEntity.status(409).body(Map.of("message",
                    "Active session exists on another device. Please logout from that device first."));
        }

        log.info("Saved new fingerprint for: {}", username);
        String token = jwtUtil.generateToken(username);
        // TODO: Add "; Secure" flag when deploying to HTTPS in production
        response.setHeader("Set-Cookie", "jwt=" + token + "; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict");
        log.info("Login successful for: {}", username);
        return ResponseEntity.ok(Map.of("message", "Login successful!"));
    }

    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        String username = (String) request.getAttribute("username");
        String incomingFingerprint = request.getHeader("X-Client-Fingerprint");

        if (username != null) {
            String storedFingerprint = sessionRegistry.getFingerprint(username);
            if (storedFingerprint != null && storedFingerprint.equals(incomingFingerprint)) {
                sessionRegistry.delete(username);
                log.info("Session deleted for: {}", username);
                response.setHeader("Set-Cookie", "jwt=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict");
                return ResponseEntity.ok(Map.of("message", "Logged out successfully!"));
            } else {
                log.warn("Logout blocked - fingerprint mismatch for: {}", username);
                return ResponseEntity.status(401).body(Map.of("message", "Logout failed - fingerprint mismatch!"));
            }
        }
        return ResponseEntity.status(401).body(Map.of("message", "Logout failed - no session found!"));
    }
}