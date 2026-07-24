package com.atch.exam.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class AntiCheatApiTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithMockUser(username = "student", roles = {"STUDENT"})
    public void testSubmitSecurityLog() throws Exception {
        String logPayload = """
                {
                    "eventType": "VIOLATION_DETECTED",
                    "data": {
                        "type": "Chuyển tab hoặc thu nhỏ trình duyệt",
                        "process": "Trình duyệt / Hệ điều hành"
                    }
                }
                """;

        mockMvc.perform(post("/api/security-logs")
                .contentType(MediaType.APPLICATION_JSON)
                .content(logPayload))
                .andExpect(status().isOk());
    }
}
