package com.atch.exam.controller;

import com.atch.exam.model.SystemConfig;
import com.atch.exam.repository.SystemConfigRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/config")
public class ConfigController {

    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @GetMapping
    public ResponseEntity<SystemConfig> getConfig() {
        SystemConfig config = systemConfigRepository.findById(1L).orElse(new SystemConfig());
        return ResponseEntity.ok(config);
    }
}
