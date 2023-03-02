package com.springboot.template.config.security;

import com.springboot.template.oauth.token.AuthTokenProvider;

import com.springboot.template.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class OAuthJwtConfig {

    private final UserRepository userRepository;

    @Value("${jwt.secret}")
    private String secret;

    @Bean
    public AuthTokenProvider jwtProvider() {
        return new AuthTokenProvider(secret, userRepository);
    }
}
