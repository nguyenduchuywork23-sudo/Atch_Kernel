package com.atch.exam.controller;

import com.atch.exam.model.User;
import com.atch.exam.repository.UserRepository;
import com.atch.exam.security.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserRepository userRepository;

    public static class LoginRequest {
        public String username;
        public String password;
        public String hwid;
    }

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody LoginRequest authRequest) throws Exception {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.username, authRequest.password)
            );
        } catch (Exception e) {
            return ResponseEntity.status(401).body(Map.of("message", "Sai tên đăng nhập hoặc mật khẩu!"));
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.username);
        final String jwt = jwtUtils.generateToken(userDetails);
        
        User user = userRepository.findByUsername(authRequest.username).orElseThrow();

        if (user.getHwid() == null && authRequest.hwid != null && !authRequest.hwid.isEmpty()) {
            user.setHwid(authRequest.hwid);
            userRepository.save(user);
            log.info("Registered new HWID for user {}", user.getUsername());
        } else if (user.getHwid() != null && !user.getHwid().equals(authRequest.hwid)) {
            log.warn("HWID mismatch for user {}. Expected: {}, Got: {}", user.getUsername(), user.getHwid(), authRequest.hwid);
            return ResponseEntity.status(403).body(Map.of("message", "Đăng nhập từ thiết bị lạ bị từ chối! Vui lòng dùng máy thi gốc."));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("token", jwt);
        response.put("role", user.getRole().replace("ROLE_", "").toLowerCase());
        response.put("name", user.getUsername());
        
        return ResponseEntity.ok(response);
    }
}
