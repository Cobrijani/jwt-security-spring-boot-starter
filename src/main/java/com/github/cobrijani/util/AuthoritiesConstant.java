package com.github.cobrijani.util;

/**
 * Default constants for authorities
 * Created by SBratic on 2/17/2017.
 */
public class AuthoritiesConstant {

  public static final String USER = "ROLE_USER";
  public static final String ANONYMOUS = "ROLE_ANONYMOUS";
  public static String ADMIN = "ROLE_ADMIN";

  private AuthoritiesConstant() {
    throw new UnsupportedOperationException();
  }

}
