package com.rtt.realtalktalk.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
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

    // AccessToken 생성
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

    // RefreshToken 생성
    public String generateRefreshToken(Authentication authentication){
        log.info("<< 리프레쉬 토큰 발급 메서드 진입 >> ");
        log.info("<< 리프레쉬 토큰 발급 메서드 진입 >> 파라미터 = " + authentication);

        String authorities = authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));

        log.info("<< 리프레쉬 토큰 발급 메서드 진입 >> authorities = " + authorities);
        log.info("<< 리프레쉬 토큰 발급 메서드 진입 >> authentication.getName() = " + authentication.getName());

        long now = (new Date()).getTime();
        Date refreshTokenExpiredTime = new Date(now + this.SEVEN_DAYS);

        return Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", authorities)
                .signWith(key, SignatureAlgorithm.HS256)
                .setExpiration(refreshTokenExpiredTime)
                .setIssuedAt(new Date())
                .compact();
    }

    // 토큰에서 유저 정보 추출 후 Authentication 객체 생성
    public Authentication getAuthentication(String token){
        log.info("<< 토큰 정보 추출 메서드 진입 >>");
        log.info("<< 토큰 정보 추출 메서드 진입 >> 파라미터 = " + token);

        Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody();

        log.info(" 토큰에서 Claim 추출 : Cliams = " + claims);

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        log.info("authorities = " + authorities);

        User principal = new User(claims.getSubject(), "", authorities);

        log.info("principal = " + principal);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);

    }


    // 토큰 검증
    public Boolean validateToken(String token){
        log.info("<< 토큰 검증 메서드 진입 >>");
        log.info("<< 토큰 검증 메서드 진입 >> 파라미터 = " + token);

        try{
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return !claims.getBody().getExpiration().before(new Date());
        }catch(SignatureException e){
            log.info("SignatureException (서명 오류 토큰) = " + e.getMessage());
            throw new JwtException("SIGNATURE_ERROR");
        }catch(MalformedJwtException e){
            log.info("MalformedJwtException (손상된 토큰) = " + e.getMessage());
            throw new JwtException("MALFORMED_ERROR");
        }catch(ExpiredJwtException e){
            log.info("ExpiredJwtException (만료된 토큰) = " + e.getMessage());
            throw new JwtException("EXPIRED_ERROR");
        }catch(IllegalArgumentException e){
            log.info("IllegalArgumentException (적절하지 않은 파라미터 에러) = " + e.getMessage());
            throw new JwtException("ILLEGAL-ARGUMENT_ERROR");
        }
    }





}
