package com.example.fingerprint_backend;

import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

@Component
public class HmacUtil {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    // computes SHA-256 hash of the request payload (used before signing)
    public String hashPayload(String payload) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    // computes HMAC-SHA256(fingerprint + payloadHash + timestamp, secret)
    public String computeSignature(String fingerprint, String payloadHash, String timestamp, String secret) {
        try {
            String dataToSign = fingerprint + payloadHash + timestamp;
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGORITHM);
            mac.init(keySpec);
            byte[] signatureBytes = mac.doFinal(dataToSign.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(signatureBytes);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute HMAC signature", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}