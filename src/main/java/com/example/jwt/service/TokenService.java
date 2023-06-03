package com.example.jwt.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.stream.Collectors;

@Service
public class TokenService {
    private final JwtEncoder encoder;

    //wstrzykujemy Bean encodera
    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

    public String generateToken(Authentication authentication) {
        Instant now = Instant.now();  //Instant reprezentuje czas z dokładnością do nanosekund bez względu na strefy czasowe
        String scope = authentication.getAuthorities().stream()  //zbiera role do Stringa
                .map(auth -> auth.getAuthority())
                .collect(Collectors.joining());

        JwtClaimsSet claims = JwtClaimsSet.builder() // ustawienia tokena
                .issuer("self") //kto wystawił
                .issuedAt(now) //kiedy wystawił
                .expiresAt(now.plus(1, ChronoUnit.HOURS)) // do kiedy wystawił
                .subject(authentication.getName()) // komu wystawił
                .claim("scope",scope) //gdzie ma dostęp
                .build();

        String tokenValue = encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue(); //wygeneruj token
        System.out.println(tokenValue);
        return tokenValue;
    }
}
