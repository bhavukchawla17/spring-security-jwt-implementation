package com.example.spring_security.util;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JWTUtil {

    private final String secret = "my-secret-key-which-is-long-32-bytes";
    private final SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));

    public String generateToken(String username, Map<String, String> claims, long expiryMinutes) {
        final JwtBuilder jwtBuilder = Jwts.builder()
        .subject(username).claims(claims)
        .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis()+expiryMinutes*60*1000))
        .signWith(key);

        return jwtBuilder.compact();
    }

    public String validateAndExtractUserName(String token) {
        try {
            System.out.println(Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload());
            return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload().getSubject();
        } catch (Exception e) {
            return null;
        }
    }
    
}
