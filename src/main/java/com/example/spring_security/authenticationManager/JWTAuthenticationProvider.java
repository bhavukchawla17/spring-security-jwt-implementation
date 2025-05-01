package com.example.spring_security.authenticationManager;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.example.spring_security.authTokens.JWTAuthenticationToken;
import com.example.spring_security.util.JWTUtil;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class JWTAuthenticationProvider implements AuthenticationProvider{

    private JWTUtil jwtUtil;
    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
        String token = (String)authentication.getCredentials();
        String userName = jwtUtil.validateAndExtractUserName(token);

        if(userName == null){
            throw new BadCredentialsException("Token is invalid or expired");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(userName);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JWTAuthenticationToken.class.isAssignableFrom(authentication);
    }

    
    
}
