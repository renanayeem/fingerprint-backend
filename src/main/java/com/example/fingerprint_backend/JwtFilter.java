package com.example.fingerprint_backend;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String token = extractCookie(request, "jwt");

        if (token != null && jwtUtil.validateToken(token)) {
            String username = jwtUtil.getUsernameFromToken(token);
            String jti = jwtUtil.getJtiFromToken(token);
            request.setAttribute("username", username);
            request.setAttribute("jti", jti);
            // informing spring security that the user is authenticated
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null,
                    new ArrayList<>());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        // done checking jwt , continue processing request
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