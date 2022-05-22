package com.enablebanking.jwtapi.controller;

import com.enablebanking.jwtapi.dto.AuthRequest;
import com.enablebanking.jwtapi.dto.AuthResponse;
import com.enablebanking.jwtapi.dto.JwtInfoResponse;
import com.enablebanking.jwtapi.service.MyUserDetailsService;
import com.enablebanking.jwtapi.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final MyUserDetailsService myUserDetailsService;
    private final JwtService jwtService;

    /**
     * Restricted resource. Should be requested with a JWT token.
     * @return
     */
    @GetMapping("/jwt")
    public ResponseEntity<JwtInfoResponse> jwtInfo() {
        final JwtInfoResponse jwtInfo = JwtInfoResponse.builder()
                .jwt(null)
                .build();
        return ResponseEntity.ok(jwtInfo);
    }

    @PostMapping("/auth")
    public ResponseEntity<AuthResponse> auth(@RequestBody AuthRequest authRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getLogin(), authRequest.getPassword()));
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(authRequest.getLogin());
        String token = jwtService.generateToken(userDetails);
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
