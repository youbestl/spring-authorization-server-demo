package com.crane.soft.resource.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

/**
 * @author DL
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/messages/**") // 设置一个安全匹配器，以 /messages 开头的请求将会受到配置保护
                .authorizeHttpRequests() // 所有请求都需要认证
                .requestMatchers("/messages/**").hasAuthority("SCOPE_message.read") // 请求需要有 message.read 权限
                .and()
                .oauth2ResourceServer()
//                .jwt(Customizer.withDefaults()); //jwtToken
                .opaqueToken(Customizer.withDefaults()); // 采用 opaqueToken
        return http.build();
    }

    @Bean
    OpaqueTokenIntrospector opaqueTokenIntrospector(RestTemplateBuilder builder, OAuth2ResourceServerProperties properties) {
        RestTemplate restTemplate = builder
                .basicAuthentication(properties.getOpaquetoken().getClientId(),
                        properties.getOpaquetoken().getClientSecret())
                .setConnectTimeout(Duration.ofSeconds(60))
                .setReadTimeout(Duration.ofSeconds(60))
                .build();
        return new NimbusOpaqueTokenIntrospector(properties.getOpaquetoken().getIntrospectionUri(), restTemplate);
    }

}
