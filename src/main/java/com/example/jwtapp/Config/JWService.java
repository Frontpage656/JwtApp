package com.example.jwtapp.Config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoder;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.print.DocFlavor;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWService {

    private static final String PRIVATE_KEY = "629f7854f1b0b7e6def70f220b925f8baf944ee61301c7b6b40bbc51c0f1bc5b";

    public String extractUserName(String token) {

        // Todo: Get the userNme from the claim
        return extractClaim(token, Claims::getSubject);

    }

    //Todo: create method which will extracts all claims from the token
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Todo: method to extract  single claim from the token
    public <T> T extractClaim(String token, Function<Claims, T> claimsTResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsTResolver.apply(claims);
    }

    //Todo: we get the key
    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(PRIVATE_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //Todo: Lets generate the token
    public String generateToken(
            Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    // Todo: If you want to generate the claim not from extra claim, but from userDetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }


    //Todo: Method to validate token
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    //Todo: lets see if the token expired
    private boolean isTokenExpired(String token) {
        return extractExpirationDate(token).before(new Date());
    }

    // Todo: we extract the expiration date from the token
    private Date extractExpirationDate(String token) {
        return extractClaim(token, Claims::getExpiration);
    }


}
