package com.example.dischord.global.jwt;


import com.example.dischord.user.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        final String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);

        logger.info("authorization = " + authorization);

        if(authorization == null || !authorization.startsWith("Bearer ")){
            logger.error("authorization 이 없습니다.");
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorization.substring(7);

        try {
            if (jwtUtil.isExpired(token)) {
                logger.error("Token 이 만료되었습니다.");
                filterChain.doFilter(request, response);
                return;
            }

            String userName = jwtUtil.getUsername(token);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(userName, null, List.of(new SimpleGrantedAuthority("ROLE_USER")));

            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);

        } catch (Exception e) {
            logger.error("JWT Token processing failed: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }


}
