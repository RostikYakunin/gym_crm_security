package com.crm.services.security;

import com.crm.models.Token;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${spring.security.jwt.secret-key}")
    private String secretKey;

    @Value("${spring.security.jwt.expiration-minutes}")
    private long expirationTimeMinutes;

    private Key key;

    @PostConstruct
    public void init() {
        var decodedKey = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(decodedKey);
    }

    public Token generateToken(UserDetails userDetails) {
        var username = userDetails.getUsername();
        var issuedAt = new Date(System.currentTimeMillis());
        var expiredAt = new Date(System.currentTimeMillis() + (expirationTimeMinutes * 60_000));
        var stingToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(issuedAt)
                .setExpiration(issuedAt)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return Token.builder()
                .ownerUserName(username)
                .issuedAt(issuedAt)
                .expiredAt(expiredAt)
                .token(stingToken)
                .build();
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        final var username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private boolean isTokenExpired(String token) {
        return extractClaim(token, Claims::getExpiration).before(new Date());
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        var claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
        return claimsResolver.apply(claims);
    }
}
