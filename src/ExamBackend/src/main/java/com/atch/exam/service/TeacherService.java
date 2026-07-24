package com.atch.exam.service;

import com.atch.exam.model.SecurityLog;
import com.atch.exam.model.User;
import com.atch.exam.repository.SecurityLogRepository;
import com.atch.exam.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class TeacherService {

    private final UserRepository userRepository;
    private final SecurityLogRepository securityLogRepository;

    @Autowired
    public TeacherService(UserRepository userRepository, SecurityLogRepository securityLogRepository) {
        this.userRepository = userRepository;
        this.securityLogRepository = securityLogRepository;
    }

    public List<User> searchStudents(String query) {
        return userRepository.searchStudents(query);
    }

    public List<SecurityLog> getStudentLogs(Long studentId) {
        return securityLogRepository.findByUserId(studentId);
    }

    public void unlockRoom(Long roomId) {
        // Implementation for enabling exams in a specific room
        System.out.println("Room " + roomId + " unlocked.");
    }
}
