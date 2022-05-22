package com.enablebanking.jwtapi.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class MyUserDetailsService implements UserDetailsService {
    private static final String USER = "foo";
    private static final String PASSWORD = "foo";

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User(USER, PASSWORD, new ArrayList<>());
    }
}
