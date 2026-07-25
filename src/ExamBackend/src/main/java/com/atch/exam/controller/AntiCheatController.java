package com.atch.exam.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class AntiCheatController {

    @PostMapping("/security-logs")
    public ResponseEntity<?> receiveSecurityLogs(@RequestBody Map<String, Object> logData) {
        // Here we could parse and save the security logs to the database.
        // For now, just logging or accepting it.
        System.out.println("Received security log: " + logData);
        return ResponseEntity.ok(Map.of("message", "Log received"));
    }
}
