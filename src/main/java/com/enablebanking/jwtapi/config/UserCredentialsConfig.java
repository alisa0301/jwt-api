package com.enablebanking.jwtapi.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@Configuration
@ConfigurationProperties(prefix = "user")
public class UserCredentialsConfig {
    private String login;
    private String password;
}
