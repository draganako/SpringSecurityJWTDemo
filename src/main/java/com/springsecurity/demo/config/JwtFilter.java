package com.springsecurity.demo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.springsecurity.demo.repo.TokenRepository;
import com.springsecurity.demo.service.JWTService;
import com.springsecurity.demo.service.impl.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final ApplicationContext context;

    private final JWTService jwtService;

    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/login") || request.getServletPath().equals("/token/refresh")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader(AUTHORIZATION);
        String token, username;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            token = authHeader.substring(7);
            username = jwtService.extractUserName(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = context.getBean(UserDetailsServiceImpl.class).loadUserByUsername(username);

                var isTokenValid = jwtService.isTokenValid(token);

                if (jwtService.validateToken(token, userDetails) && isTokenValid) {
                    //String[] roles = jwtService.extractRoles();
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//                stream(roles).forEach(role -> {
//                        authorities.add(new SimpleGrantedAuthority(role));
//                });

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, authorities);//userDetails.getAuthorities()
                    authToken.setDetails(new WebAuthenticationDetailsSource()
                            .buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            response.setHeader("error", e.getMessage());
            response.setStatus(HttpStatus.FORBIDDEN.value());

            Map<String, String> errors = new HashMap<>();
            errors.put("error_message", e.getMessage());
            response.setContentType(APPLICATION_JSON_VALUE);
            new ObjectMapper().writeValue(response.getOutputStream(), errors);
        }

        filterChain.doFilter(request, response);
    }
}
