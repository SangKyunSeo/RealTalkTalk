package com.rtt.realtalktalk.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.stream.Collectors;

@Component
@Slf4j
public class TokenProvider {
    private final Key key;
    private final Long THIRTY_MINUTES = 60 * 1000 * 30L;
    private final Long SEVEN_DAYS = 60 * 1000 * 60 * 24 * 7L;

    // 초기화
    public TokenProvider(@Value("${jwt.secret}") String secretKey){
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // 토큰 생성
    public String generateAccessToken(Authentication authentication){
        log.info("<< 엑세스 토큰 발급 메서드 진입 >>");
        log.info("<< 엑세스 토큰 발급 메서드 진입 >> 파라미터 : Authentication = " + authentication);

        String authorities = authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        log.info("<< 엑세스 토큰 발급 메서드 진입 >> authorities = " + authorities);
        log.info("<< 엑세스 토큰 발급 메서드 진입 >> authentication.getName() = " + authentication.getName());

        long now = (new Date()).getTime();
        Date accessTokenExpiredTime = new Date(now + this.THIRTY_MINUTES);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .signWith(key, SignatureAlgorithm.HS256)
                .setExpiration(accessTokenExpiredTime)
                .setIssuedAt(new Date())
                .compact();
    }



}
