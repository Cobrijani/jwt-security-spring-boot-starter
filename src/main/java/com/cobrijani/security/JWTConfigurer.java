package com.cobrijani.security;

import com.cobrijani.properties.JwtSecurityProperties;
import lombok.AllArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security configuration that adds {@link JWTFilter}
 * Created by SBratic on 10/30/2016.
 */
@AllArgsConstructor
public class JWTConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    private final TokenProvider tokenProvider;

    private final JwtSecurityProperties jwtProperties;


    @Override
    public void configure(HttpSecurity builder) throws Exception {
        JWTFilter jwtFilter = new JWTFilter(tokenProvider, jwtProperties);
        builder.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
