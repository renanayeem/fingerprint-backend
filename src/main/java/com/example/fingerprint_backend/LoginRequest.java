package com.example.fingerprint_backend;

import jakarta.validation.constraints.NotBlank;

public class LoginRequest {

    @NotBlank(message = "Username is required!")
    private String username;

    @NotBlank(message = "Password is required!")
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