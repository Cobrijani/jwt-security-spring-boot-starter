package com.cobrijani.services;

import com.cobrijani.model.SimpleUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

/**
 * Simple user details service created just so execution does not break
 * Created by SBratic on 2/18/2017.
 */
@Service
public class SimpleUserDetailService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<String> username = Optional.ofNullable(s);
        return username.map(x -> new SimpleUserDetails(x, x.toCharArray(), Collections.emptyList())).orElse(null);
    }
}
