package com.github.cobrijani;

import com.github.cobrijani.security.TokenProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.test.util.EnvironmentTestUtils;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;

/**
 * Tests for {@link JwtAutoConfiguration}
 *
 * @author Stefan Bratic
 */
public class JwtSecurityAutoconfigureApplicationTests {


  private AnnotationConfigApplicationContext context;


  @Before
  public void setUp() {
    this.context = new AnnotationConfigApplicationContext();
  }

  @After
  public void tearDown() {
    if (this.context != null) {
      this.context.close();
    }
  }

  /**
   * Checks whether beans are registered after auto configuration class has been registered
   */
  @Test
  public void registerJwtAutoConfiguration() {
    this.context.register(SecurityProperties.class);
    this.context.register(JwtAutoConfiguration.class);
    this.context.refresh();

    //assert
    this.context.getBean(TokenProvider.class);
    this.context.getBean(PasswordEncoder.class);
    this.context.getBean(UserDetailsService.class);
    this.context.getBean(SecurityEvaluationContextExtension.class);
    this.context.getBean(WebSecurityConfigurerAdapter.class);
  }

  /**
   * Expects no to have bean provided by auto configuration if auto configuration is not loaded
   */
  @Test(expected = NoSuchBeanDefinitionException.class)
  public void nonRegisterJwtAutoConfiguration() {
    this.context.refresh();

    //assert
    this.context.getBean(TokenProvider.class);
  }

  /**
   * Expects not to have {@link WebSecurityConfigurerAdapter} in context if property is set to false
   */
  @Test(expected = NoSuchBeanDefinitionException.class)
  public void propertyAutoSecurityDisabled() {
    this.context.register(SecurityProperties.class);
    this.context.register(JwtAutoConfiguration.class);
    EnvironmentTestUtils.addEnvironment(this.context, "com.github.cobrijani.jwt.enabled:false");
    this.context.refresh();

    //assert
    this.context.getBean(WebSecurityConfigurerAdapter.class);
  }

}
