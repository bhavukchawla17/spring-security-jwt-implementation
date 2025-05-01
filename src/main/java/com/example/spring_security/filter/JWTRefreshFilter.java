package com.example.spring_security.filter;

import java.io.IOException;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.spring_security.authTokens.JWTAuthenticationToken;
import com.example.spring_security.util.JWTUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;

import java.util.Map;

@AllArgsConstructor
public class JWTRefreshFilter extends OncePerRequestFilter{

    private JWTUtil jwtUtil;
    private AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
                
        if(!request.getServletPath().equals("/refresh-token")){
            filterChain.doFilter(request, response);
            return;
        }

        String jwtToken = extractJWTFromRequest(request);
        if(jwtToken != null){
            Authentication authentication = authenticationManager.authenticate(new JWTAuthenticationToken(jwtToken));
            if(authentication.isAuthenticated()){
                String newJwtToken = jwtUtil.generateToken(authentication.getName(), Map.of(), 10);
                response.addHeader("Authentication", "Bearer " + newJwtToken);
            }
        }
        else{
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        }
    }

    String extractJWTFromRequest(HttpServletRequest request){
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        if(cookies != null) {
            for(jakarta.servlet.http.Cookie cookie : cookies){
                if(cookie.getName().equals("refreshToken")){
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    
    
}
