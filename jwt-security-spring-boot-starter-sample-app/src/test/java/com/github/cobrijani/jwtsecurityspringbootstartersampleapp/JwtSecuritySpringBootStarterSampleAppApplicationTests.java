package com.github.cobrijani.jwtsecurityspringbootstartersampleapp;

import com.github.cobrijani.model.AuthenticationRequestBody;
import com.github.cobrijani.model.SimpleUserDetails;
import com.github.cobrijani.security.JWTToken;
import com.github.cobrijani.security.TokenProvider;
import io.restassured.RestAssured;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

import java.util.Collections;

import static io.restassured.RestAssured.given;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class JwtSecuritySpringBootStarterSampleAppApplicationTests {

  private static final String VALID_USERNAME = "validUsername";
  private static final String VALID_PASSWORD = "validPassword";
  private static final String INVALID_USERNAME = "invalidUsername";
  private static final String INVALID_PASSWORD = "invalidPassword";

  @Autowired
  private TokenProvider provider;

  @MockBean
  private UserDetailsService userDetailsService;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @MockBean
  private AuthenticationManager authenticationManager;

  @LocalServerPort
  private int port;

  @Before
  public void init() {
    RestAssured.port = port;
    Mockito.when(userDetailsService.loadUserByUsername(Mockito.anyString()))
      .then(new Answer<UserDetails>() {
        /**
         * @param invocation the invocation on the mock.
         * @return the value to be returned
         * @throws Throwable the throwable to be thrown
         */
        @Override
        public UserDetails answer(InvocationOnMock invocation) throws Throwable {
          String username = invocation.getArgumentAt(0, String.class);
          if (username.equals(VALID_USERNAME)) {
            return new SimpleUserDetails(VALID_USERNAME, passwordEncoder.encode(VALID_PASSWORD).toCharArray(), Collections.emptyList());
          } else {
            throw new UsernameNotFoundException("User not found");
          }
        }
      });

    Mockito.when(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(VALID_USERNAME, VALID_PASSWORD)))
      .thenAnswer(new Answer<Authentication>() {
        /**
         * @param invocation the invocation on the mock.
         * @return the value to be returned
         * @throws Throwable the throwable to be thrown
         */
        @Override
        public Authentication answer(InvocationOnMock invocation) throws Throwable {
          String username = invocation.getArgumentAt(0, String.class);
          String password = invocation.getArgumentAt(1, String.class);

          if (username.equals(VALID_USERNAME) && password.equals(VALID_PASSWORD)) {
            return new UsernamePasswordAuthenticationToken(username, password, Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
          } else {
            throw new BadCredentialsException("Bad credentials");
          }
        }
      });


  }

  @After
  public void tearDown() {
    RestAssured.reset();
  }


  @Test
  public void contextLoads() {

  }

  @Test
  public void successfulAuthenticateReturnsToken() {
    JWTToken token =
      given()
        .body(new AuthenticationRequestBody() {
          @Override
          public String getLogin() {
            return VALID_USERNAME;
          }

          @Override
          public String getPassword() {
            return VALID_PASSWORD;
          }

          @Override
          public boolean isRememberMe() {
            return false;
          }
        })
        .post("/api/v1/login")
        .as(JWTToken.class);

    assertNotNull(token);
    assertNotNull(token.getIdToken());
    assertTrue(provider.validateToken(token.getIdToken()));
  }

  @Test
  public void unsuccessfulAuthenticateReturnsError() {

  }

}
