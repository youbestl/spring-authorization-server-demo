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
                .securityMatcher("/messages/**") // 设置一个安全匹配器，以 /messages 开头的请求将会受到配置保护
                .authorizeHttpRequests() // 所有请求都需要认证
                .requestMatchers("/messages/**").hasAuthority("SCOPE_message.read") // 请求需要有 message.read 权限
                .and()
                .oauth2ResourceServer()
                .jwt(Customizer.withDefaults());
        return http.build();
    }
}
