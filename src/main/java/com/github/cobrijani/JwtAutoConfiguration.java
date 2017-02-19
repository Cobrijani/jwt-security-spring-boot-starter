package com.github.cobrijani;

import com.github.cobrijani.properties.JwtSecurityProperties;
import com.github.cobrijani.security.Http401UnauthorizedEntryPoint;
import com.github.cobrijani.security.JJWTTokenProvider;
import com.github.cobrijani.security.JWTConfigurer;
import com.github.cobrijani.security.TokenProvider;
import com.github.cobrijani.services.SimpleUserDetailService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.data.repository.query.SecurityEvaluationContextExtension;

/**
 * Main class that triggers auto configuration
 * Created by SBratic on 2/17/2017.
 */
@Configuration
@ConditionalOnClass({WebSecurityConfigurerAdapter.class, AuthenticationManager.class,
        GlobalAuthenticationConfigurerAdapter.class})
@EnableConfigurationProperties({JwtSecurityProperties.class})
public class JwtAutoConfiguration {

    private final JwtSecurityProperties jwtSecurityProperties;


    public JwtAutoConfiguration(JwtSecurityProperties jwtSecurityProperties) {
        this.jwtSecurityProperties = jwtSecurityProperties;
    }

    @Bean
    @ConditionalOnMissingBean(Http401UnauthorizedEntryPoint.class)
    public Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint() {
        return new Http401UnauthorizedEntryPoint();
    }


    @Bean
    @ConditionalOnMissingBean(TokenProvider.class)
    public TokenProvider tokenProvider() {
        return new JJWTTokenProvider(jwtSecurityProperties);
    }


    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    public UserDetailsService userDetailsService() {
        return new SimpleUserDetailService();
    }

    @Bean
    @ConditionalOnMissingBean(SecurityEvaluationContextExtension.class)
    public SecurityEvaluationContextExtension securityEvaluationContextExtension() {
        return new SecurityEvaluationContextExtension();
    }

    /**
     * Default Jwt based security configuration
     */
    @Configuration
    @EnableWebSecurity
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @ConditionalOnProperty(prefix = "com.cobrijani.jwt", name = "enabled", matchIfMissing = true)
    protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {

        protected final SecurityProperties security;

        private final JwtSecurityProperties jwtSecurityProperties;

        private final Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint;

        private final PasswordEncoder passwordEncoder;

        private final UserDetailsService userDetailsService;

        private final TokenProvider tokenProvider;


        public SecurityConfiguration(SecurityProperties security,
                                     JwtSecurityProperties jwtSecurityProperties,
                                     Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint,
                                     PasswordEncoder passwordEncoder, UserDetailsService userDetailsService,
                                     TokenProvider tokenProvider, TokenProvider tokenProvider1) {
            this.security = security;
            this.jwtSecurityProperties = jwtSecurityProperties;
            this.http401UnauthorizedEntryPoint = http401UnauthorizedEntryPoint;
            this.passwordEncoder = passwordEncoder;
            this.userDetailsService = userDetailsService;
            this.tokenProvider = tokenProvider1;
        }

        /**
         * Override this method to configure the {@link HttpSecurity}. Typically subclasses
         * should not invoke this method by calling super as it may override their
         * configuration. The default configuration is:
         * <p>
         * <pre>
         * http.authorizeRequests().anyRequest().authenticated().and().formLogin().and().httpBasic();
         * </pre>
         *
         * @param http the {@link HttpSecurity} to modify
         * @throws Exception if an error occurs
         */
        @Override
        protected void configure(HttpSecurity http) throws Exception {

            if (this.security.isRequireSsl()) {
                http.requiresChannel().anyRequest().requiresSecure();
            }
            if (!this.security.isEnableCsrf()) {
                http.csrf().disable();
            }

            http.exceptionHandling()
                    .authenticationEntryPoint(http401UnauthorizedEntryPoint)
                    .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .apply(new JWTConfigurer(tokenProvider, jwtSecurityProperties, authenticationManagerBean()));
        }


        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth
                    .userDetailsService(userDetailsService)
                    .passwordEncoder(passwordEncoder);
        }
    }
}
