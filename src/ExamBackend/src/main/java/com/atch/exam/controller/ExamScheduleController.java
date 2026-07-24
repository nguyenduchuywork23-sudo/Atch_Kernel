package com.atch.exam.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/exam-schedules")
public class ExamScheduleController {

    @GetMapping
    public String getAllExamSchedules() {
        return "List of all exam schedules";
    }
}
