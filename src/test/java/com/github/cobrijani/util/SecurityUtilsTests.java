package com.github.cobrijani.util;

import io.jsonwebtoken.lang.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Stefan Bratić <cobrijani@gmail.com>
 * Created on 12/29/2017.
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class SecurityUtilsTests {

  /**
   * Test whether {@link SecurityUtils#getCurrentUserLogin()}
   * returns null when no authentication is set in the {@link org.springframework.security.core.context.SecurityContext}
   */
  @Test
  public void currentLoginEmptyContext() {
    String login = SecurityUtils.getCurrentUserLogin();

    Assert.isNull(login);
  }

  /**
   * Test that checks {@link SecurityUtils#getCurrentUserLogin()}
   * if returns username of the authentication that is present
   * in the {@link org.springframework.security.core.context.SecurityContext}
   */
  @Test
  @WithMockUser(username = "pera")
  public void currentLoginJWTToken() {
    String login = SecurityUtils.getCurrentUserLogin();

    Assert.isTrue("pera".equals(login));
  }

  /**
   * When anonymous user is present in the {@link org.springframework.security.core.context.SecurityContext}
   * <p>
   * method {@link SecurityUtils#getCurrentUserLogin()} should return null for the login
   */
  @Test
  @WithAnonymousUser()
  public void currentLoginAnonymous() {

    String login = SecurityUtils.getCurrentUserLogin();

    Assert.isNull(login);

  }
}
