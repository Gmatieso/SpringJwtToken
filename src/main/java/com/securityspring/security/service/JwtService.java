package com.securityspring.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtService {
    public static  final String SECRET = "357638792F423F4428472B4B6250655368566D597133743677397A2443264629";

    // takes JWT token as input and extracts the subject
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // extracts the expiration date from the JWT token claims i.e determines whether the token has expired or not
    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
    //generic mmethod to extract a specific claim from the JWT token's claim
    private <T> T  extractClaim(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);

    }
   // parses the JWT token and extract all of its claims.
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // checkes whether a JWT token has expired by comparing the token's expiration date to current date
    private  Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    //  validates JWT token by extracts the username from token and check whether it matches the username
    public  Boolean validateToken(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
    // Generates a JWT Token
    public String GenerateToken(String username){
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

    // create JWT Token
    private String createToken(Map<String, Object> claims, String username) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 1))
                .signWith(getSignKey(), SignatureAlgorithm.HS256).compact();
    }

    //obtain the signing key for jwt token creation  & validation
    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
