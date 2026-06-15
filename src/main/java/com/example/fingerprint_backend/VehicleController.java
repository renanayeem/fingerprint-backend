package com.example.fingerprint_backend;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class VehicleController {

    private final VehicleService vehicleService;

    public VehicleController(VehicleService vehicleService) {
        this.vehicleService = vehicleService;
    }

    @GetMapping("/vehicles")
    public ResponseEntity<?> getVehicles(HttpServletRequest request) {
        String username = (String) request.getAttribute("username");
        List<Vehicle> vehicles = vehicleService.getVehicles(username);
        return ResponseEntity.ok(vehicles);
    }

    @PostMapping("/vehicles")
    public ResponseEntity<Map<String, String>> addVehicle(
            @RequestBody VehicleRequest request,
            HttpServletRequest httpRequest) {
        try {
            String username = (String) httpRequest.getAttribute("username");
            vehicleService.addVehicle(username, request);
            return ResponseEntity.ok(Map.of("message", "Vehicle added successfully!"));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body(Map.of("message", e.getMessage()));
        }
    }
}