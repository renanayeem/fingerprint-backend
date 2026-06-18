package com.example.fingerprint_backend;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class SessionRegistry {

    private final RedisTemplate<String, String> redisTemplate;
    private static final String FINGERPRINT_PREFIX = "session:fingerprint:";
    private static final String IP_PREFIX = "session:ip:";

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

    public void saveIp(String sessionId, String ip) {
        redisTemplate.opsForValue().set(IP_PREFIX + sessionId, ip, Duration.ofHours(24));
    }

    public String getIp(String sessionId) {
        return redisTemplate.opsForValue().get(IP_PREFIX + sessionId);
    }

    public void delete(String sessionId) {
        redisTemplate.delete(FINGERPRINT_PREFIX + sessionId);
        redisTemplate.delete(IP_PREFIX + sessionId);
    }
}