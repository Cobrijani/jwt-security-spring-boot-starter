package com.github.cobrijani.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

import static io.vavr.API.*;
import static io.vavr.Predicates.instanceOf;


/**
 * Helper methods for security
 * Created by SBratic on 10/31/2016.
 */
public class SecurityUtils {

  private SecurityUtils() {
    throw new UnsupportedOperationException();
  }

  /**
   * Get the login of the current user.
   *
   * @return the login of the current user
   */
  public static String getCurrentUserLogin() {
    return getCurrentAuthentication()
      .map(x ->
        Match(x).of(
          Case($(instanceOf(UserDetails.class)), z -> ((UserDetails) z).getUsername()),
          Case($(instanceOf(String.class)), y -> (String) y.getPrincipal()),
          Case($(), o -> null)
        )).orElse(null);
  }

  /**
   * Check if a user is authenticated.
   *
   * @return true if the user is authenticated, false otherwise
   */
  public static boolean isAuthenticated() {
    return getCurrentAuthentication()
      .map(Authentication::getAuthorities)
      .map(x -> x.stream().noneMatch(y -> y.getAuthority().equals(AuthoritiesConstant.ANONYMOUS)))
      .orElse(false);
  }

  private static Optional<Authentication> getCurrentAuthentication() {
    return Optional.of(SecurityContextHolder.getContext())
      .map(SecurityContext::getAuthentication);
  }

  /**
   * If the current user has a specific authority (security role).
   * <p>
   * <p>The name of this method comes from the isUserInRole() method in the Servlet API</p>
   *
   * @param authority the authority to check
   * @return true if the current user has the authority, false otherwise
   */
  public static boolean isCurrentUserInRole(final String authority) {
    return getCurrentAuthentication()
      .map(Authentication::getPrincipal)
      .filter(x -> x instanceof UserDetails)
      .map(x -> (UserDetails) x)
      .map(UserDetails::getAuthorities)
      .map(x -> x.contains(new SimpleGrantedAuthority(authority)))
      .orElse(false);
  }
}
