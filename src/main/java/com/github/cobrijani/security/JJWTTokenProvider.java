package com.github.cobrijani.security;

import com.github.cobrijani.properties.JwtSecurityProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.vavr.control.Try;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Implementation of {@link TokenProvider} with {@link io.jsonwebtoken} library
 * Created by SBratic on 10/29/2016.
 */
@Slf4j
@Service
public class JJWTTokenProvider implements TokenProvider {

  private final JwtSecurityProperties jwtProperties;
  private long tokenValidityInSecondsForRememberMe;
  private long tokenValidityInSeconds;

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
    long now = System.currentTimeMillis();

    return rememberMe ? new Date(now + this.tokenValidityInSecondsForRememberMe) : new Date(now + this.tokenValidityInSeconds);
  }


  @Override
  public String createToken(Authentication authentication, Boolean rememberMe) {

    Optional<Authentication> auth = Optional.ofNullable(authentication);

    String authorities = extractAuthorities(auth.map(Authentication::getAuthorities).orElseThrow(IllegalArgumentException::new));

    Date validity = provideValidityDate(rememberMe);

    String subject = auth.map(Authentication::getName).orElseThrow(IllegalArgumentException::new);

    JwtBuilder jwtBuilder = Jwts.builder()
      .setSubject(subject)
      .signWith(SignatureAlgorithm.HS256, jwtProperties.getToken().getSecret())
      .setExpiration(validity);

    if (!"".equals(authorities.trim())) {
      jwtBuilder.claim(jwtProperties.getToken().getPayload().getAuthoritiesKey(), authorities);
    }

    return jwtBuilder.compact();
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
      Try.of(() ->
        Arrays.stream(claims.get(jwtProperties.getToken().getPayload().getAuthoritiesKey()).toString().split(","))
          .map(SimpleGrantedAuthority::new)
          .collect(Collectors.toList())
      ).recover(ex ->
        Collections.emptyList()
      ).get();

    User principal = new User(claims.getSubject(), "", authorities);

    return new UsernamePasswordAuthenticationToken(principal, "", authorities);
  }
}
