package com.atch.exam.controller;

import com.atch.exam.model.SecurityLog;
import com.atch.exam.repository.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/security-logs")
public class SecurityLogController {

    @Autowired
    private SecurityLogRepository securityLogRepository;

    @PostMapping
    public ResponseEntity<?> createSecurityLog(@RequestBody SecurityLog logData) {
        logData.setTimestamp(LocalDateTime.now());
        securityLogRepository.save(logData);
        return ResponseEntity.ok().build();
    }
}
