package com.example.jwt.controller;

import com.example.jwt.service.TokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
public class AuthController {
    private static final Logger LOG = LoggerFactory.getLogger(AuthController.class); //przygotuj loggera dla tej klasy
    private final TokenService tokenService;

    public AuthController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping("/token")
    public String token(Authentication authentication) { //obiekt ze wszystkimi danymi dotyczącymi zalogowania
        System.out.println("Token requested for: " + authentication.getName());
        LOG.debug("Token requested for user: '{}'", authentication.getName()); //logowanie zdarzen
        String token = tokenService.generateToken(authentication);
        LOG.debug("Token granted: {}", token);
        return token;
    }
}
