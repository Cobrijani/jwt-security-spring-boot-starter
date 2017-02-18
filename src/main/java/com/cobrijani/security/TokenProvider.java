package com.cobrijani.security;

import org.springframework.security.core.Authentication;

/**
 * Service that manipulates with Json Web Tokens
 * Created by SBratic on 10/31/2016.
 */
public interface TokenProvider {

    String createToken(Authentication authentication, Boolean rememberMe);

    boolean validateToken(String token);

    Authentication getAuthentication(String token);

}
