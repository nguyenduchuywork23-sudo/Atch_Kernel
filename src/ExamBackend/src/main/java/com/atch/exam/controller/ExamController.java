package com.atch.exam.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.http.ResponseEntity;
import org.springframework.beans.factory.annotation.Autowired;
import com.atch.exam.repository.ExamSessionRepository;
import com.atch.exam.model.ExamSession;
import java.time.LocalDateTime;
import java.time.Duration;

@RestController
@RequestMapping("/api/exams")
public class ExamController {

    @Autowired
    private ExamSessionRepository examSessionRepository;

    @PostMapping("/submit/{sessionId}")
    public ResponseEntity<?> submitExam(@PathVariable Long sessionId, @RequestBody(required = false) Object submissionData) {
        ExamSession session = examSessionRepository.findById(sessionId).orElse(null);
        if (session == null) {
            return ResponseEntity.badRequest().body("Session not found");
        }
        
        if (session.getStartTime() != null) {
            long minutesSinceStart = Duration.between(session.getStartTime(), LocalDateTime.now()).toMinutes();
            if (minutesSinceStart < 1) {
                return ResponseEntity.badRequest().body("Cannot submit within 1 minute of starting");
            }
        }
        
        session.setStatus("COMPLETED");
        session.setEndTime(LocalDateTime.now());
        examSessionRepository.save(session);
        return ResponseEntity.ok("Submitted successfully");
    }
}
