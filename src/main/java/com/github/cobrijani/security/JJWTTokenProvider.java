package com.github.cobrijani.security;

import com.github.cobrijani.properties.JwtSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import javaslang.control.Try;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

/**
 * Implementation of {@link TokenProvider} with {@link io.jsonwebtoken} library
 * Created by SBratic on 10/29/2016.
 */
@Slf4j
@Service
public class JJWTTokenProvider implements TokenProvider {

    private long tokenValidityInSecondsForRememberMe;

    private long tokenValidityInSeconds;

    private final JwtSecurityProperties jwtProperties;

    public JJWTTokenProvider(JwtSecurityProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }


    @PostConstruct
    public void init() {
        this.tokenValidityInSeconds = 1000 * jwtProperties.getToken().getTokenValidityInSeconds();
        this.tokenValidityInSecondsForRememberMe = 1000 * jwtProperties.getToken().getTokenValidityInSecondsForRememberMe();
    }


    private String extractAuthorities(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
    }

    private Date provideValidityDate(Boolean rememberMe) {
        long now = (new Date()).getTime();
        return rememberMe ? new Date(now + this.tokenValidityInSecondsForRememberMe) : new Date(now + this.tokenValidityInSeconds);
    }


    @Override
    public String createToken(Authentication authentication, Boolean rememberMe) {
        String authorities = extractAuthorities(authentication.getAuthorities());
        Date validity = provideValidityDate(rememberMe);

        String subject = authentication.getName();


        return Jwts.builder()
                .setSubject(subject)
                .claim(jwtProperties.getToken().getPayload().getAuthoritiesKey(), authorities)
                .signWith(SignatureAlgorithm.HS256, jwtProperties.getToken().getSecret())
                .setExpiration(validity)
                .compact();
    }


    @Override
    public boolean validateToken(String token) {
        return Try.of(() -> {
            Jwts.parser().setSigningKey(jwtProperties.getToken().getSecret()).parseClaimsJws(token);
            return true;
        }).recover(ex -> {
            log.info(String.format("Invalid JWT signature : %s", ex.getMessage()));
            return false;
        }).get();
    }

    @Override
    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtProperties.getToken().getSecret())
                .parseClaimsJws(token)
                .getBody();


        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());


        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }
}
