package com.example.fingerprint_backend;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class FingerprintFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(FingerprintFilter.class);

    private final SessionRegistry sessionRegistry;
    private final HmacUtil hmacUtil;

    public FingerprintFilter(SessionRegistry sessionRegistry, HmacUtil hmacUtil) {
        this.sessionRegistry = sessionRegistry;
        this.hmacUtil = hmacUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // Skip fingerprint validation for public endpoints
        if (path.equals("/api/login")
                || path.equals("/api/register")
                || path.equals("/api/logout")
                || path.equals("/api/refresh")) {

            filterChain.doFilter(request, response);
            return;
        }

        String incomingFingerprint = request.getHeader("X-Client-Fingerprint");
        String username = (String) request.getAttribute("username");
        String jti = (String) request.getAttribute("jti");

        // Missing authentication/fingerprint information
        if (username == null || jti == null || incomingFingerprint == null) {
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Missing fingerprint information");
            return;
        }

        String rotatedFingerprint = hmacUtil.hashPayload(incomingFingerprint + jti);

        String expectedFingerprint = sessionRegistry.getFingerprint(username);

        if (expectedFingerprint == null || !expectedFingerprint.equals(rotatedFingerprint)) {
            response.sendError(
                    HttpServletResponse.SC_UNAUTHORIZED,
                    "Fingerprint mismatch");
            return;
        }

        // IP soft validation - log only, never block
        String currentIp = request.getRemoteAddr();
        String knownIp = sessionRegistry.getIp(username);

        if (knownIp != null && !knownIp.equals(currentIp)) {
            log.warn(
                    "IP changed mid-session for {}: was {}, now {}",
                    username,
                    knownIp,
                    currentIp);
        }

        filterChain.doFilter(request, response);
    }
}