package com.springsecurity.demo.service;

import com.springsecurity.demo.model.User;
import com.springsecurity.demo.repo.UserRepository;
import com.springsecurity.demo.service.impl.UserDetailsServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

@Service
@RequiredArgsConstructor
public class UserService {

    private final JWTService jwtService;

    private final AuthenticationManager authManager;

    private final UserRepository userRepository;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    private final ApplicationContext context;

    public Map.Entry<User, Boolean> register(User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        //user.setRole(Role.USER);

        User existingUser = userRepository.findByUsername(user.getUsername());
        if (existingUser != null) {
            return Map.entry(existingUser, false);
        }

        userRepository.save(user);

        return Map.entry(user, true);

    }

    public Map<String, String> verify(User user) {
        Map<String, String> response = new HashMap<>();

        Authentication authentication = authManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword()));

        User userStored = userRepository.findByUsername(user.getUsername());

        if (authentication.isAuthenticated()) {
            String accessToken = jwtService.generateToken(userStored.getUsername(), new HashMap<>());
            response.put("access_token", accessToken);
            response.put("refresh_token", jwtService.generateToken(userStored.getUsername(), new HashMap<>()));//DIFFERENT!!

            jwtService.revokeAllUserTokens(userStored.getId());
            jwtService.saveUserToken(userStored, accessToken);
        }

        return response;
    }

    public Map<String, String> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        String authHeader = request.getHeader(AUTHORIZATION);
        String refreshToken, username;

        Map<String, String> tokens = new HashMap<>();

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            refreshToken = authHeader.substring(7);

            if (!jwtService.isTokenValid(refreshToken))
                return tokens;

            username = jwtService.extractUserName(refreshToken);

            if (username != null) {
                UserDetails userDetails = context.getBean(UserDetailsServiceImpl.class).loadUserByUsername(username);

                if (jwtService.validateToken(refreshToken, userDetails)) {
                    String accessToken = jwtService.generateToken(userDetails.getUsername(), new HashMap<>());

                    tokens.put("refresh_token", refreshToken);
                    tokens.put("access_token", accessToken);

                    jwtService.revokeAllUserTokens(((User) userDetails).getId());
                    jwtService.saveUserToken((User) userDetails, accessToken);

                }
            }
        }

        return tokens;
    }

    public void deleteUser(Integer userId) {
        userRepository.deleteById(userId);
    }
}
