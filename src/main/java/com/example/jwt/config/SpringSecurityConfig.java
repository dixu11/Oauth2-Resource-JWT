package com.example.jwt.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig {

    private final RsaKeyProperties rsaKeys; //zawiera klucz prywatny i publiczny

    public SpringSecurityConfig(RsaKeyProperties rsaKeys) {
        this.rsaKeys = rsaKeys;
    }


    /*@Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }*/
    @Bean
    JwtDecoder jwtDecoder() { //wykorzystywany przez Resource Server do sprawdzania tokenów z użyciem publiczengo klucza
        return NimbusJwtDecoder.withPublicKey(rsaKeys.publicKey()).build();
    }

    @Bean
    JwtEncoder jwtEncoder() { //encoder potrzebny przez Authentication Server do wydawania tokenów (u nas klasa TokenService)
        JWK jwk = new RSAKey.Builder(rsaKeys.publicKey())//z naszego obiektu reprezentującego klucze wstawiamy do obiektu rozumianego przez Security (JWK)
                .privateKey(rsaKeys.privateKey())
                .build();
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk))); //przekazujemy zbiór z jednym elementem i tworzymy standardowy Encoder tokenów
    }

    @Bean
    public InMemoryUserDetailsManager userDetails() {
        return new InMemoryUserDetailsManager(
                User.withUsername("dixu")
                        .password("{noop}123") //wskazanie dla squrity którego encodera wykorzystać
                        // w tym przypadku takiego który nie koduje w ogóle, bez tego domyślnie nie działa
                        //można zrobić to klasycznie przez stworzenie własnego bean Bcrypt, wstrzyknęcie go i użycie metody encode
                        .roles("me")
                        .build()

        );
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
       return http.csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(customizer ->
                        customizer.anyRequest().authenticated()  //wszystkie enpointy zablokowane domyślnie
                        )
                    //konfigurowanie resource servera - odpowiedzialnego za sprawdzanie tokenów (odkodowywanie)
               .oauth2ResourceServer(customizer -> customizer.jwt(Customizer.withDefaults())) //but needs JwtDecoder
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //important when csrf disabled ( rest is stateless anyway...)
                .httpBasic(Customizer.withDefaults()) // podstawowy sposób zabezpieczenia Rest Api - przekazywanie username i password w nagłówkach zapytania
                .build();

    }

}

/*
basic setup
    @Bean
    public InMemoryUserDetailsManager userDetails() {
        return new InMemoryUserDetailsManager(
                User.withUsername("dixu")
                        .password("{noop}123")
                        .roles("me")
                        .build()

        );
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        return http.csrf(customizer -> customizer.disable())
                .authorizeHttpRequests(custiomizer ->
                        custiomizer.anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(Customizer.withDefaults())
                .build();

    }*/
