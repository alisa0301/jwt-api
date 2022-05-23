package com.enablebanking.jwtapi.service;

import com.enablebanking.jwtapi.config.UserCredentialsConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@RequiredArgsConstructor
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {
    private final UserCredentialsConfig userCredentialsConfig;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return new User(userCredentialsConfig.getLogin(), userCredentialsConfig.getPassword(), new ArrayList<>());
    }
}
