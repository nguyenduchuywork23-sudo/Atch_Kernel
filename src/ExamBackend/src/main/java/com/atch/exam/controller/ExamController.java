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

        org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        if (session.getUser() == null) {
            throw new org.springframework.security.access.AccessDeniedException("Session has no associated user.");
        }
        if (auth == null || !auth.isAuthenticated() || !auth.getName().equals(session.getUser().getUsername())) {
            return ResponseEntity.status(403).body("Forbidden: You cannot submit someone else's exam.");
        }
        
        if ("COMPLETED".equals(session.getStatus())) {
            return ResponseEntity.badRequest().body("Exam already completed");
        }
        
        if (session.getStartTime() != null) {
            long minutesSinceStart = Duration.between(session.getStartTime(), LocalDateTime.now()).toMinutes();
            if (minutesSinceStart < 1) {
                return ResponseEntity.badRequest().body("Cannot submit within 1 minute of starting");
            }
            if (session.getExam() != null && session.getExam().getDurationMinutes() != null) {
                if (minutesSinceStart > session.getExam().getDurationMinutes() + 5) {
                    return ResponseEntity.badRequest().body("Time limit exceeded");
                }
            }
        }
        
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            session.setSubmissionData(mapper.writeValueAsString(submissionData));
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Invalid submission data");
        }
        
        session.setStatus("COMPLETED");
        session.setEndTime(LocalDateTime.now());
        examSessionRepository.save(session);
        return ResponseEntity.ok("Submitted successfully");
    }
}
