package com.rtt.realtalktalk.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
@Component
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final TokenProvider tokenProvider;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("<< JwtAuthenticationFilter 진입 >>");

        String jwt = resolveToken(request);
        String requestURI = request.getRequestURI();

        log.info("JWT : " + jwt);
        log.info("RequestURI : " + requestURI);

        if(jwt != null && tokenProvider.validateToken(jwt)){
            if(!requestURI.equals("api/regenerateToken")){
                Authentication authentication = tokenProvider.getAuthentication(jwt);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request){
        String token = request.getHeader("Authorization");

        if(token != null && token.startsWith("Bearer ")){
            return token.substring(7);
        }
        return null;
    }

}
