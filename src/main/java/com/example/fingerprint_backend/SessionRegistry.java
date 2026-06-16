package com.example.fingerprint_backend;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class SessionRegistry {

    private final RedisTemplate<String, String> redisTemplate;
    private static final String FINGERPRINT_PREFIX = "session:fingerprint:";
    private static final String SECRET_PREFIX = "session:secret:";

    public SessionRegistry(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public boolean saveFingerprintIfAbsent(String sessionId, String fingerprintHash) {
        Boolean saved = redisTemplate.opsForValue().setIfAbsent(
                FINGERPRINT_PREFIX + sessionId,
                fingerprintHash,
                Duration.ofHours(24));
        return Boolean.TRUE.equals(saved);
    }

    public String getFingerprint(String sessionId) {
        return redisTemplate.opsForValue().get(FINGERPRINT_PREFIX + sessionId);
    }

    public void saveSecret(String sessionId, String secret) {
        redisTemplate.opsForValue().set(SECRET_PREFIX + sessionId, secret, Duration.ofHours(24));
    }

    public String getSecret(String sessionId) {
        return redisTemplate.opsForValue().get(SECRET_PREFIX + sessionId);
    }

    public void delete(String sessionId) {
        redisTemplate.delete(FINGERPRINT_PREFIX + sessionId);
        redisTemplate.delete(SECRET_PREFIX + sessionId);
    }
}