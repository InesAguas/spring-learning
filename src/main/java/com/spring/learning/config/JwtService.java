package com.spring.learning.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "Qeea1cfY6vohjnHIjC7pC5NwSG45QMY25OuHkNrTFf4GLR5dk4RdPyHYEmijXTxg8J7Ltfh3U438igYjvtVpTJIia1b7LvNpvL1LwomsWTeT2f3vJowUGFhVwu1QTuYfqm8VBPLDSaeVyp2jYnS58AGbsefm3fprma9N9foQb6mq8q1idRJ2pAEcw5Dvu768IAS63eeAvBRZB2cWrfxxn6bIbQv4dMgOqcy2Sdm8IR1Rs3SsxllCBkjY0uV9BcI1";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); //subject should be the email (aka username)
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //token valid for 24h
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); //compact generates and returns the token
    }


    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
