package com.atch.exam.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class TeacherApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "teacher", roles = {"TEACHER"})
    public void testSearchStudentsWithTeacherRole() throws Exception {
        mockMvc.perform(get("/api/teacher/students/search")
                .param("query", "test"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "student", roles = {"STUDENT"})
    public void testSearchStudentsWithStudentRole() throws Exception {
        mockMvc.perform(get("/api/teacher/students/search")
                .param("query", "test"))
                .andExpect(status().isForbidden());
    }
}
