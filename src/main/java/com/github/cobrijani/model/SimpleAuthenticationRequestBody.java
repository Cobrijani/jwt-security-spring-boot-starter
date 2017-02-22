package com.github.cobrijani.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Simple implementation of {@link AuthenticationRequestBody}
 * Created by SBratic on 2/19/2017.
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class SimpleAuthenticationRequestBody implements AuthenticationRequestBody {

  private String login;

  private String password;

  private boolean rememberMe;

}
