package com.sop.chapter10.authservice.services;

import com.sop.chapter10.authservice.entities.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private String expirationTime;

    private Key key;

    @PostConstruct
    public void init(){
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public Claims getAllClaimsFromToken(String token){
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();
    }

    public Date getExpirationDateFromToken(String token){
            return getAllClaimsFromToken(token).getExpiration();
    }

    private boolean isTokenExpired(String token){
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public String generate(User userVD, String type){
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", userVD.getId());
        claims.put("role", userVD.getRole());
        return doGenerateToken(claims, userVD.getEmail(), type);
    }

    private String doGenerateToken(Map<String, Object> claims, String username, String type){
        long expirationTimeLong;
        if("Access".equals(type)){
            expirationTimeLong = Long.parseLong(expirationTime)*1000;
        } else{
            expirationTimeLong = Long.parseLong(expirationTime)*1000*5;
        }
        final Date createDate = new Date();
        final Date expireDate = new Date(createDate.getTime()+expirationTimeLong);

        return Jwts.builder().setClaims(claims).setSubject(username).setIssuedAt(createDate).setExpiration(expireDate).signWith(key).compact();
    }

    public Boolean validateToken(String token){
        return !isTokenExpired(token);
    }


}
