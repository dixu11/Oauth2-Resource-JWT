package com.example.jwt.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class MyRestController {

    @GetMapping("/test")
    public String getData(Principal principal) { // Principal - użytkownik z perspektywy spring security
//        SecurityContextHolder.getContext().getAuthentication().getPrincipal()  -- sposób aby samodzielnie dostać się do użytkownika
        return "Hello JWT" + principal.getName();
    }
}
