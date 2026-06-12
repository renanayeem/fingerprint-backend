package com.example.fingerprint_backend;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class SessionRegistry {

    private final RedisTemplate<String, String> redisTemplate;
    private static final String PREFIX = "session:fingerprint:";

    public SessionRegistry(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void saveFingerprint(String sessionId, String fingerprintHash) {
        redisTemplate.opsForValue().set(PREFIX + sessionId, fingerprintHash, Duration.ofHours(24));
    }

    public String getFingerprint(String sessionId) {
        return redisTemplate.opsForValue().get(PREFIX + sessionId);
    }

    public void delete(String sessionId) {
        redisTemplate.delete(PREFIX + sessionId);
    }
}