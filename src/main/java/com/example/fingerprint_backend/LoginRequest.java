package com.example.fingerprint_backend;

public class LoginRequest {
    private String username;
    private String password;
    private String fingerprint;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getFingerprint() {
        return fingerprint;
    }

}
