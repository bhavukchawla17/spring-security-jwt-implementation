package com.example.spring_security.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.spring_security.authenticationManager.JWTAuthenticationProvider;
import com.example.spring_security.filter.JWTAuthenticationFilter;
import com.example.spring_security.filter.JWTRefreshFilter;
import com.example.spring_security.filter.JWTValidationFilter;
import com.example.spring_security.util.JWTUtil;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    JWTUtil jwtUtil;

    // When this bean is defined the application properties user wont be created.
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails1 = User.builder()
                .username("root")
                .password(new BCryptPasswordEncoder().encode("root"))
                .build();

        return new InMemoryUserDetailsManager(userDetails1);
    }

    // Filter chain for /register endpoint - no session creation
    @Bean
    public SecurityFilterChain registerFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {

        JWTAuthenticationFilter jwtAuthenticationFilter = new JWTAuthenticationFilter(authenticationManager, jwtUtil);
        JWTValidationFilter jwtValidationFilter = new JWTValidationFilter(authenticationManager);
        JWTRefreshFilter jwtRefreshFilter = new JWTRefreshFilter(jwtUtil, authenticationManager);

        return http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/generate-token").permitAll()
                .anyRequest().authenticated()
            )
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf->csrf.disable())
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)     
            .addFilterAfter(jwtValidationFilter, JWTAuthenticationFilter.class)       
            .addFilterBefore(jwtRefreshFilter, JWTValidationFilter.class)
            .build();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }

    @Bean
    public JWTAuthenticationProvider jwtAuthenticationProvider(UserDetailsService userDetailsService) {
        JWTAuthenticationProvider jwtAuthenticationProvider = new JWTAuthenticationProvider(jwtUtil, userDetailsService);
        return jwtAuthenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider daoAuthenticationProvider,
                                                    JWTAuthenticationProvider jwtAuthenticationProvider) {
        return new ProviderManager(List.of(daoAuthenticationProvider, jwtAuthenticationProvider));
    }
}