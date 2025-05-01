package com.example.spring_security.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PostMapping;



@RestController
@RequestMapping("/users")
public class DummyUserController {

    @PostMapping
    public String postMethodName() {
        return new String();
    }
    
    
    
}
