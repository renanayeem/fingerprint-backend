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
    private final HmacUtil hmacUtil;

    public AuthService(SessionRegistry sessionRegistry, JwtUtil jwtUtil, UserService userService, HmacUtil hmacUtil) {
        this.sessionRegistry = sessionRegistry;
        this.jwtUtil = jwtUtil;
        this.userService = userService;
        this.hmacUtil = hmacUtil;
    }

    public ResponseEntity<Map<String, String>> login(LoginRequest request, HttpServletRequest httpRequest,
            HttpServletResponse response) {
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

        String token = jwtUtil.generateToken(username);
        String jti = jwtUtil.getJtiFromToken(token);
        String rotatedFingerprint = hmacUtil.hashPayload(fingerprint + jti);

        boolean saved = sessionRegistry.saveFingerprintIfAbsent(username, rotatedFingerprint);

        if (!saved) {
            log.info("Session already exists for: {}", username);
            return ResponseEntity.status(409).body(Map.of("message",
                    "Active session exists on another device. Please logout from that device first."));
        }

        log.info("Saved new rotated fingerprint for: {}", username);

        String loginIp = httpRequest.getRemoteAddr();
        sessionRegistry.saveIp(username, loginIp);
        log.info("Saved login IP for {}: {}", username, loginIp);

        // TODO: Add "; Secure" flag when deploying to HTTPS in production
        response.setHeader("Set-Cookie", "jwt=" + token + "; HttpOnly; Path=/; Max-Age=86400");
        log.info("Login successful for: {}", username);

        return ResponseEntity.ok(Map.of("message", "Login successful!"));
    }

    public ResponseEntity<Map<String, String>> logout(HttpServletRequest request, HttpServletResponse response) {
        String username = (String) request.getAttribute("username");
        String jti = (String) request.getAttribute("jti");
        String incomingFingerprint = request.getHeader("X-Client-Fingerprint");

        if (username != null && jti != null && incomingFingerprint != null) {
            String rotatedFingerprint = hmacUtil.hashPayload(incomingFingerprint + jti);
            String storedFingerprint = sessionRegistry.getFingerprint(username);
            if (storedFingerprint != null && storedFingerprint.equals(rotatedFingerprint)) {
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