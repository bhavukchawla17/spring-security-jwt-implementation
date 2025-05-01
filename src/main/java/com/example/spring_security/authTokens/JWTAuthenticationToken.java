package com.example.spring_security.authTokens;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class JWTAuthenticationToken extends AbstractAuthenticationToken{

    private String token;

    public JWTAuthenticationToken(String token){
        super(null);
        this.token = token;
        this.setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
       return token;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    
    
}
