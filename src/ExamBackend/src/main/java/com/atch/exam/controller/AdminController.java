package com.atch.exam.controller;

import com.atch.exam.model.SystemConfig;
import com.atch.exam.model.User;
import com.atch.exam.repository.SystemConfigRepository;
import com.atch.exam.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/admin")
public class AdminController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @Autowired
    private org.springframework.security.crypto.password.PasswordEncoder passwordEncoder;

    @PostMapping("/users")
    public ResponseEntity<User> createUser(@RequestBody User user) {
        if (user.getPassword() != null && !user.getPassword().isEmpty()) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }
        return ResponseEntity.ok(userRepository.save(user));
    }

    @DeleteMapping("/users/{id}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        if (userRepository.existsById(id)) {
            userRepository.deleteById(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }
    @Autowired
    private SystemConfigRepository systemConfigRepository;

    @PostMapping("/config")
    public ResponseEntity<SystemConfig> updateConfig(@RequestBody SystemConfig config) {
        SystemConfig existing = systemConfigRepository.findById(1L).orElse(new SystemConfig());
        existing.setId(1L);
        existing.setTargetExamUrl(config.getTargetExamUrl());
        return ResponseEntity.ok(systemConfigRepository.save(existing));
    }
}
