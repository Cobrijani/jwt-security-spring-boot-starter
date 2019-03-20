package com.github.cobrijani.security;

import com.github.cobrijani.properties.JwtSecurityProperties;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Unit tests for {@link TokenProvider}
 *
 * @author Stefan Bratic
 */
public class TokenProviderTests {

  private JJWTTokenProvider tokenProvider;

  private JwtSecurityProperties jwtSecurityProperties;

  @Before
  public void setUp() {
    this.jwtSecurityProperties = new JwtSecurityProperties();
    this.tokenProvider = new JJWTTokenProvider(jwtSecurityProperties);
    this.tokenProvider.init();
  }

  @After
  public void tearDown() {
    this.jwtSecurityProperties = null;
    this.tokenProvider = null;
  }


  @Test
  public void createTokenHappyFlow() {
    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("pera", "pera");
    String jwt = tokenProvider.createToken(token, true);

    Assert.assertNotNull("String not empty", jwt);
    Assert.assertTrue(this.tokenProvider.validateToken(jwt));

    Authentication auth = this.tokenProvider.getAuthentication(jwt);

    Assert.assertEquals(token.getName(), auth.getName());
    Assert.assertEquals("", auth.getCredentials());
  }


  @Test(expected = IllegalArgumentException.class)
  public void createTokenEmptyAuth() {
    tokenProvider.createToken(null, false);
  }

  @Test
  public void validateTokenFalse() {
    String invalidJwt = "invalidJwt";

    Assert.assertFalse(this.tokenProvider.validateToken(invalidJwt));
  }


  @Test(expected = MalformedJwtException.class)
  public void getAuthenticationInvalidToken() {
    String invalidJwt = "invalidJwt";

    this.tokenProvider.getAuthentication(invalidJwt);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getAuthenticationNullValue() {
    this.tokenProvider.getAuthentication(null);
  }


}
