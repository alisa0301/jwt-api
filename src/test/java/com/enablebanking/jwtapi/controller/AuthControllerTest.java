package com.enablebanking.jwtapi.controller;

import com.enablebanking.jwtapi.config.JwtCredentialsConfig;
import com.enablebanking.jwtapi.config.UserCredentialsConfig;
import com.enablebanking.jwtapi.dto.AuthRequest;
import com.enablebanking.jwtapi.dto.AuthResponse;
import com.enablebanking.jwtapi.service.JwtService;
import com.enablebanking.jwtapi.service.UserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private AuthController authController;
    @Autowired
    private UserCredentialsConfig userCredentialsConfig;
    @Autowired
    private JwtCredentialsConfig jwtCredentialsConfig;
    @Autowired
    private UserDetailsService userDetailsService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    ObjectMapper objectMapper;

    @Test
    public void shouldNotAuthorizeWhenCredentialsAreEmpty() {
        AuthRequest authRequest = new AuthRequest();
        assertThrows(BadCredentialsException.class, () -> authController.auth(authRequest));
    }

    @Test
    public void shouldNotAuthorizeWhenCredentialsAreNotValid() {
        AuthRequest authRequest = new AuthRequest(
                "pho", "bo"
        );
        assertThrows(BadCredentialsException.class, () -> authController.auth(authRequest));
    }

    @Test
    public void shouldAuthorizeWhenCredentialsAreValid() {
        AuthRequest authRequest = new AuthRequest(
                userCredentialsConfig.getLogin(), userCredentialsConfig.getPassword()
        );
        ResponseEntity<AuthResponse> auth = authController.auth(authRequest);
        assertEquals(auth.getStatusCode(), HttpStatus.OK);
        assertFalse(auth.getBody().getJwt().isEmpty());
    }

    @Test
    public void shouldBeResourcesRestrictedWhenTokenIsNotSent() throws Exception {
        this.mockMvc.perform(get("/jwt")).andExpect(status().isForbidden());
    }


    @Test
    public void shouldBeResourcesAllowedWhenTokenIsValid() throws Exception {
        MvcResult mvcResult = this.mockMvc.perform(
                post("/auth")
                        .contentType("application/json")
                        .content("{\"login\": \"foo\", \"password\": \"foo\"}")
        ).andExpect(status().isOk()).andReturn();
        String contentAsString = mvcResult.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(contentAsString, AuthResponse.class);
        assertTrue(authResponse.getJwt().length() > 0);
    }
}