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

    private final Map<String, Integer> loginAttempts = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, Long> lockoutTime = new java.util.concurrent.ConcurrentHashMap<>();

    @PostMapping("/login")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody LoginRequest authRequest) throws Exception {
        String username = authRequest.username;
        if (lockoutTime.containsKey(username) && System.currentTimeMillis() < lockoutTime.get(username)) {
            return ResponseEntity.status(429).body(Map.of("message", "Tài khoản bị khóa tạm thời do nhập sai quá nhiều lần."));
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, authRequest.password)
            );
            loginAttempts.remove(username);
            lockoutTime.remove(username);
        } catch (Exception e) {
            int attempts = loginAttempts.getOrDefault(username, 0) + 1;
            loginAttempts.put(username, attempts);
            if (attempts >= 5) {
                lockoutTime.put(username, System.currentTimeMillis() + 15 * 60 * 1000); // 15 mins
            }
            return ResponseEntity.status(401).body(Map.of("message", "Sai tên đăng nhập hoặc mật khẩu!"));
        }

        final UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        final String jwt = jwtUtils.generateToken(userDetails);
        
        User user = userRepository.findByUsername(username).orElseThrow();

        if (authRequest.hwid == null || authRequest.hwid.isEmpty()) {
            return ResponseEntity.status(400).body(Map.of("message", "HWID is required."));
        }

        if (user.getHwid() == null) {
            // Require strict checking or explicit bind. We will allow bind if it's the first time but we should log it and maybe in a real scenario use OTP.
            // For now, let's keep auto-bind but add a check if we want to disable it.
            // Task says: "Do not blindly auto-bind on first login. Instead, require an explicit bind mechanism or strict checking."
            // Let's just reject if HWID is null and tell them to contact Admin.
            return ResponseEntity.status(403).body(Map.of("message", "Tài khoản chưa được liên kết thiết bị. Vui lòng liên hệ Admin."));
        } else if (!user.getHwid().equals(authRequest.hwid)) {
            log.warn("HWID mismatch for user {}. Expected: {}, Got: {}", user.getUsername(), user.getHwid(), authRequest.hwid);
            return ResponseEntity.status(403).body(Map.of("message", "Đăng nhập từ thiết bị lạ bị từ chối! Vui lòng dùng máy thi gốc."));
        }

        Map<String, Object> response = new HashMap<>();
        response.put("token", jwt);
        response.put("role", user.getRole().replace("ROLE_", "").toLowerCase());
        response.put("name", user.getUsername());
        
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String token) {
        if (token != null && token.startsWith("Bearer ")) {
            jwtUtils.invalidateToken(token.substring(7));
        }
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
