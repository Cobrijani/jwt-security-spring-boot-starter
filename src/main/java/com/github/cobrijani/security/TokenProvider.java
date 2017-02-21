package com.github.cobrijani.security;

import org.springframework.security.core.Authentication;

/**
 * Service that manipulates with Json Web Tokens
 * Created by SBratic on 10/31/2016.
 */
public interface TokenProvider {

    /**
     * Creates token based on authentication details
     *
     * @param authentication authenticatioon details
     * @param rememberMe     is user remember me
     * @return json web token
     */
    String createToken(Authentication authentication, Boolean rememberMe);

    /**
     * Checks whether token is valid
     *
     * @param token token to be checked
     * @return is valid or not
     */
    boolean validateToken(String token);

    /**
     * Extract authentication from token
     *
     * @param token token to be extracted from
     * @return authentication details
     */
    Authentication getAuthentication(String token);

}
