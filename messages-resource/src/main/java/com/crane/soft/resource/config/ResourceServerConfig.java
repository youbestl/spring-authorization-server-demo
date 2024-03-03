package com.crane.soft.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author DL
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/messages/**")
                .authorizeHttpRequests() // 所有请求都需要认证
                .requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
                .and()
                .oauth2ResourceServer()
                .jwt(Customizer.withDefaults());
        return http.build();
    }
}
