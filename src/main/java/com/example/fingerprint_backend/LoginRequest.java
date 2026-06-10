package com.example.fingerprint_backend;

public class LoginRequest {
    private String username;
    private String password;
    private String fingerprint;
    private String name;
    private String email;
    private String phone;
    private String address;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public String getName() {
        return name;
    }

    public String getEmail() {
        return email;
    }

    public String getPhone() {
        return phone;
    }

    public String getAddress() {
        return address;
    }
}