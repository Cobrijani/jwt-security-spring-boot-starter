package com.cobrijani.security;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Model that represents token
 * Created by SBratic on 11/3/2016.
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class JWTToken {

    private String idToken;

}
