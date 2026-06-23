package com.example.fingerprint_backend;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Component
public class HmacFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(HmacFilter.class);
    private static final long MAX_TIMESTAMP_DRIFT_MS = 5 * 60 * 1000; // 5 minutes

    private final HmacUtil hmacUtil;
    private final String sharedSecret;

    public HmacFilter(HmacUtil hmacUtil, @Value("${hmac.secret}") String sharedSecret) {
        this.hmacUtil = hmacUtil;
        this.sharedSecret = sharedSecret;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        boolean needsSignature = (method.equals("POST") && path.equals("/api/vehicles"));

        if (!needsSignature) {
            filterChain.doFilter(request, response);
            return;
        }

        String fingerprint = request.getHeader("X-Client-Fingerprint");
        String signature = request.getHeader("X-Signature");
        String timestamp = request.getHeader("X-Timestamp");

        if (fingerprint == null || signature == null || timestamp == null) {
            log.warn("HMAC verification failed - missing required fields for path: {}", path);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing signature headers");
            return;
        }

        if (!isTimestampFresh(timestamp)) {
            log.warn("HMAC verification failed - stale timestamp for path: {}", path);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Request expired");
            return;
        }

        // read the raw body ONCE into our own byte array
        byte[] bodyBytes = request.getInputStream().readAllBytes();
        String body = new String(bodyBytes, StandardCharsets.UTF_8);
        String payloadHash = hmacUtil.hashPayload(body);

        String expectedSignature = hmacUtil.computeSignature(fingerprint, payloadHash, timestamp, sharedSecret);

        if (!expectedSignature.equals(signature)) {
            log.warn("HMAC verification failed - signature mismatch for path: {}", path);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid signature");
            return;
        }

        // re-wrap the request so the controller can still read the body normally,
        // backed by the bytes we already consumed above
        HttpServletRequest replayableRequest = new HttpServletRequestWrapper(request) {
            @Override
            public ServletInputStream getInputStream() {
                return new ServletInputStream() {
                    private final ByteArrayInputStream buffer = new ByteArrayInputStream(bodyBytes);

                    @Override
                    public int read() {
                        return buffer.read();
                    }

                    @Override
                    public boolean isFinished() {
                        return buffer.available() == 0;
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setReadListener(ReadListener readListener) {
                        // not needed for this use case
                    }
                };
            }
        };

        filterChain.doFilter(replayableRequest, response);
    }

    private boolean isTimestampFresh(String timestampStr) {
        try {
            long timestamp = Long.parseLong(timestampStr);
            long now = System.currentTimeMillis();
            return Math.abs(now - timestamp) <= MAX_TIMESTAMP_DRIFT_MS;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}