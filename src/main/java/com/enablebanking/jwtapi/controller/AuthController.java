package com.enablebanking.jwtapi.controller;

import com.enablebanking.jwtapi.dto.AuthRequest;
import com.enablebanking.jwtapi.dto.AuthResponse;
import com.enablebanking.jwtapi.dto.JwtInfoResponse;
import com.enablebanking.jwtapi.service.JwtService;
import com.enablebanking.jwtapi.service.UserDetailsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final JwtService jwtService;

    /**
     * Restricted resource. Should be requested with a JWT token.
     *
     * @return
     */
    @GetMapping("/jwt")
    public ResponseEntity<JwtInfoResponse> jwtInfo(
            @RequestHeader("Authorization") String authHeader,
            HttpServletResponse response
    ) {
        String jwt = jwtService.getJwtFromHeader(authHeader);
        if (jwt == null) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
        }
        return ResponseEntity.ok(jwtService.getClaims(jwt));
    }

    @PostMapping("/auth")
    public ResponseEntity<AuthResponse> auth(@RequestBody AuthRequest authRequest) {
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                authRequest.getLogin(), authRequest.getPassword()
        );
        authenticationManager.authenticate(authToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(authRequest.getLogin());
        String token = jwtService.generateToken(userDetails);
        return ResponseEntity.ok(new AuthResponse(token));
    }
}
