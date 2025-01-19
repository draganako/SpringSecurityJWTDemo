package com.springsecurity.demo.controller;

import com.springsecurity.demo.model.User;
import com.springsecurity.demo.service.JWTService;
import com.springsecurity.demo.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.Map;


@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final JWTService jwtService;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody User user) {
        try {
            Map.Entry<User, Boolean> registerResult = userService.register(user);

            if (!registerResult.getValue())
                return new ResponseEntity<>(HttpStatus.CONFLICT);
            else
                return new ResponseEntity<>(registerResult.getKey(), HttpStatus.OK);
        } catch(IllegalArgumentException e) {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody User user) throws Exception {
        try {
            Map<String, String> tokens = userService.verify(user);
            return new ResponseEntity<>(tokens, HttpStatus.OK);
        }
        catch(Exception e) {
            return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
        }
    }

    @GetMapping("/token/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            Map<String, String> tokens = userService.refreshToken(request, response);
            if (!tokens.isEmpty())
                return new ResponseEntity<>(tokens, HttpStatus.OK);
            else
                return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
        }
        catch(Exception e) {
            return new ResponseEntity<>(null, HttpStatus.UNAUTHORIZED);
        }
    }

    @DeleteMapping("/user")
    public ResponseEntity<?> deleteUser(@RequestParam Integer userId) {
        jwtService.revokeAllUserTokens(userId);
        userService.deleteUser(userId);
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }
}
