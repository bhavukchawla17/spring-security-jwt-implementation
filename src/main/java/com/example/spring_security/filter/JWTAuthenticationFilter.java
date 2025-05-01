package com.example.spring_security.filter;

import java.io.IOException;
import java.util.Map;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.spring_security.model.LoginRequest;
import com.example.spring_security.util.JWTUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;


@AllArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter{

    private AuthenticationManager authenticationManager;
    private JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        if(!request.getServletPath().equals("/generate-token")) {
            filterChain.doFilter(request, response);
            return;
        }

        ObjectMapper objectMapper = new ObjectMapper();
        LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(), LoginRequest.class);

        UsernamePasswordAuthenticationToken token = 
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        Authentication authenticate = authenticationManager.authenticate(token);
        if(authenticate.isAuthenticated()){
            //generate token
            String jwtToken = jwtUtil.generateToken(authenticate.getName(), Map.of("DummyKey", "DummyValue"), 10);
            response.addHeader("Authentication", "Bearer " + jwtToken);

            String refreshToken = jwtUtil.generateToken(authenticate.getName(), Map.of(), 7*24*60);
            Cookie cookie = new Cookie("refreshToken", refreshToken);
            cookie.setHttpOnly(true);
            cookie.setSecure(true);
            cookie.setPath("/refresh-token");
            cookie.setMaxAge(7*24*60);
            response.addCookie(cookie);
        }
    }
}