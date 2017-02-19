package com.github.Cobrijani.security;

import com.github.Cobrijani.properties.JwtSecurityProperties;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
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

    private final AuthenticationManager authenticationManager;

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        final JWTFilter jwtFilter = new JWTFilter(tokenProvider, jwtProperties);
        final JWTLoginFilter jwtLoginFilter = new JWTLoginFilter(jwtProperties.getUrl(), tokenProvider, jwtProperties, authenticationManager);

        builder.addFilterBefore(jwtLoginFilter, UsernamePasswordAuthenticationFilter.class);
        builder.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
