package com.github.Cobrijani.security;

import com.github.Cobrijani.properties.JwtSecurityProperties;
import lombok.AllArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Optional;

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


        Optional.ofNullable(jwtProperties.getToken().getTokenHeader())
                .map(request::getHeader)
                .filter(StringUtils::hasText)
                .filter(x -> x.startsWith(jwtProperties.getToken().getTokenSchema()))
                .map(x -> x.substring(jwtProperties.getToken().getTokenSchema().length(), x.length()))
                .filter(this.tokenProvider::validateToken)
                .map(this.tokenProvider::getAuthentication)
                .ifPresent(SecurityContextHolder.getContext()::setAuthentication);

        filterChain.doFilter(servletRequest, servletResponse);
    }

}
