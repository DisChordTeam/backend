package com.example.dischord.global.jwt;


import io.jsonwebtoken.Jwts;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;


@Component
public class JWTUtil {

    private SecretKey secretKey;

    @Value("${spring.jwt.access.expiration}")
    private Long accessTokenValidTime;

    @Value("${spring.jwt.refresh.expiration}")
    private Long refreshTokenValidTime;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {

        secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());
    }



    public String createAccessToken(String username) {
        Date now = new Date();

        return Jwts.builder()
                .claim("email", username)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + accessTokenValidTime))
                .signWith(secretKey)
                .compact();
    }

    public String createRefreshJwtToken(String username) {
        Date now = new Date();

        return Jwts.builder()
                .claim("username", username)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + refreshTokenValidTime))
                .signWith(secretKey)
                .compact();
    }


    public String getUsername(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("email", String.class);
    }

    public Boolean isExpired(String token) {

        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }


}