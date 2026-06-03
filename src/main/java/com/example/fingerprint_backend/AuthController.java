package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    @GetMapping("/data")
    public ResponseEntity<Map<String, String>> getData(
            @RequestHeader(value = "X-Client-Fingerprint", required = false) String fingerprint) {

        System.out.println("Fingerprint received: " + fingerprint);
        return ResponseEntity.ok(Map.of("message", "Data fetched successfully! Fingerprint: " + fingerprint));
    }

    @PostMapping("/data")
    public ResponseEntity<Map<String, String>> postData(
            @RequestHeader(value = "X-Client-Fingerprint", required = false) String fingerprint) {

        System.out.println("Fingerprint received: " + fingerprint);
        return ResponseEntity.ok(Map.of("message", "Data posted successfully! Fingerprint: " + fingerprint));
    }
}