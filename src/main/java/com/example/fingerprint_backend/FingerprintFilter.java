package com.example.fingerprint_backend;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

@Component
public class FingerprintFilter extends OncePerRequestFilter {

    private final SessionRegistry sessionRegistry;

    public FingerprintFilter(SessionRegistry sessionRegistry) {
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        if (path.equals("/api/login") || path.equals("/api/register")) {
            filterChain.doFilter(request, response);
            return;
        }

        String incomingFingerprint = extractCookie(request, "fingerprint");
        String username = (String) request.getAttribute("username");

        if (username == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String expectedFingerprint = sessionRegistry.getFingerprint(username);

        if (expectedFingerprint == null || !expectedFingerprint.equals(incomingFingerprint)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Fingerprint mismatch");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String extractCookie(HttpServletRequest request, String name) {
        if (request.getCookies() == null)
            return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> c.getName().equals(name))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }
}
