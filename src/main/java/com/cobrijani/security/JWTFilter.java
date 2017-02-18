package com.cobrijani.security;

import com.cobrijani.properties.JwtSecurityProperties;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * {@link GenericFilterBean} that checks if header contains token and add it to {@link SecurityContextHolder}
 * Created by SBratic on 10/30/2016.
 */
@AllArgsConstructor
public class JWTFilter extends GenericFilterBean {

    private final TokenProvider tokenProvider;

    private final JwtSecurityProperties jwtProperties;


    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;

        String token = resolveToken(request);

        if (StringUtils.hasText(token) && this.tokenProvider.validateToken(token)) {
            Authentication authentication = this.tokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(servletRequest, servletResponse);
    }

    private String resolveToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(jwtProperties.getToken().getTokenHeader());
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(jwtProperties.getToken().getTokenSchema())) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}
