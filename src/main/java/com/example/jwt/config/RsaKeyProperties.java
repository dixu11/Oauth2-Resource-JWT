package com.example.jwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

//record - klasa która automatycznie ma pola (to podane w nawiesie) konstruktor do nich i getery
@ConfigurationProperties(prefix = "rsa")  //zaczytaj z konfiguracji wszystko z przedrostkiem "rsa" do pól, i zrób BEAN
public record RsaKeyProperties(RSAPublicKey publicKey, RSAPrivateKey privateKey) {

}
