package com.example.fingerprint_backend;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;

@Service
public class VehicleService {

    private static final Logger log = LoggerFactory.getLogger(VehicleService.class);

    private final VehicleRepository vehicleRepository;

    public VehicleService(VehicleRepository vehicleRepository) {
        this.vehicleRepository = vehicleRepository;
    }

    // get all vehicles for a user
    public List<Vehicle> getVehicles(String username) {
        return vehicleRepository.findByOwnerUsername(username);
    }

    // add a new vehicle
    public void addVehicle(String username, VehicleRequest request) {
        Vehicle vehicle = new Vehicle();
        vehicle.setOwnerUsername(username);
        vehicle.setVehicleName(request.getVehicleName());
        vehicle.setVehicleNumber(request.getVehicleNumber());
        vehicle.setVehicleType(request.getVehicleType());
        vehicleRepository.save(vehicle);
        log.info("Vehicle added for: {}", username);
    }
}