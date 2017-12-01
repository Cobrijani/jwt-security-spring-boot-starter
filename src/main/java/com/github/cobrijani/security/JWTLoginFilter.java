package com.github.cobrijani.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.cobrijani.model.AuthenticationRequestBody;
import com.github.cobrijani.properties.JwtSecurityProperties;
import io.vavr.control.Try;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

/**
 * Authentication entry point in the system
 * Created by SBratic on 2/19/2017.
 */
public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

  private final TokenProvider tokenProvider;

  private final JwtSecurityProperties jwtSecurityProperties;


  protected JWTLoginFilter(String defaultFilterProcessesUrl,
                           TokenProvider tokenProvider,
                           JwtSecurityProperties jwtSecurityProperties,
                           AuthenticationManager authenticationManager) {
    super(new AntPathRequestMatcher(defaultFilterProcessesUrl));
    this.tokenProvider = tokenProvider;
    this.jwtSecurityProperties = jwtSecurityProperties;
    setAuthenticationManager(authenticationManager);
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws AuthenticationException, IOException, ServletException {

    Optional<? extends AuthenticationRequestBody> requestBody = Try.of(() ->
      Optional.ofNullable(new ObjectMapper().readValue(httpServletRequest.getInputStream(),
        jwtSecurityProperties.getAuthenticationRequestBody()))
    ).recover(ex ->
      Optional.empty()
    ).get();

    final UsernamePasswordAuthenticationToken token =
      new UsernamePasswordAuthenticationToken(requestBody.map(AuthenticationRequestBody::getLogin).orElse(null),
        requestBody.map(AuthenticationRequestBody::getPassword).orElse(null));

    token.setDetails(requestBody.map(AuthenticationRequestBody::isRememberMe));

    return getAuthenticationManager().authenticate(token);
  }

  @Override
  protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

    SecurityContextHolder.getContext().setAuthentication(authResult);

    boolean rememberMe = Try.of(authResult::getDetails)
      .map(x -> (Boolean) x)
      .recover(ex -> false).get();

    final String token = tokenProvider
      .createToken(authResult, rememberMe);

    response.addHeader(jwtSecurityProperties.getToken().getTokenHeader(),
      jwtSecurityProperties.getToken().getTokenSchema() + token);
  }
}
