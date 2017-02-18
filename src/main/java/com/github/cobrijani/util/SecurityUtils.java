package com.github.cobrijani.util;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

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
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Authentication authentication = securityContext.getAuthentication();
    String userName = null;
    if (authentication != null) {
      if (authentication.getPrincipal() instanceof UserDetails) {
        UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
        userName = springSecurityUser.getUsername();
      } else if (authentication.getPrincipal() instanceof String) {
        userName = (String) authentication.getPrincipal();
      }
    }
    return userName;
  }

  /**
   * Check if a user is authenticated.
   *
   * @return true if the user is authenticated, false otherwise
   */
  public static boolean isAuthenticated() {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Collection<? extends GrantedAuthority> authorities = securityContext.getAuthentication().getAuthorities();

    return !(authorities != null && authorities.stream().anyMatch(x -> x.getAuthority().equals(AuthoritiesConstant.ANONYMOUS)));
  }

  /**
   * If the current user has a specific authority (security role).
   * <p>
   * <p>The name of this method comes from the isUserInRole() method in the Servlet API</p>
   *
   * @param authority the authority to check
   * @return true if the current user has the authority, false otherwise
   */
  public static boolean isCurrentUserInRole(String authority) {
    SecurityContext securityContext = SecurityContextHolder.getContext();
    Authentication authentication = securityContext.getAuthentication();
    if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
      UserDetails springSecurityUser = (UserDetails) authentication.getPrincipal();
      return springSecurityUser.getAuthorities().contains(new SimpleGrantedAuthority(authority));
    }
    return false;
  }
}
