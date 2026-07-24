package com.atch.exam.controller;

import com.atch.exam.model.SecurityLog;
import com.atch.exam.model.User;
import com.atch.exam.service.TeacherService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/teacher")
public class TeacherController {

    private final TeacherService teacherService;

    @Autowired
    public TeacherController(TeacherService teacherService) {
        this.teacherService = teacherService;
    }

    @GetMapping("/students/search")
    public ResponseEntity<List<User>> searchStudents(@RequestParam("query") String query) {
        List<User> students = teacherService.searchStudents(query);
        return ResponseEntity.ok(students);
    }

    @GetMapping("/logs/{studentId}")
    public ResponseEntity<List<SecurityLog>> getStudentLogs(@PathVariable("studentId") Long studentId) {
        List<SecurityLog> logs = teacherService.getStudentLogs(studentId);
        return ResponseEntity.ok(logs);
    }

    @org.springframework.web.bind.annotation.PostMapping("/unlock")
    public ResponseEntity<String> unlockRoom(@RequestParam("roomId") Long roomId) {
        teacherService.unlockRoom(roomId);
        return ResponseEntity.ok("Exams in room " + roomId + " enabled successfully");
    }
}
