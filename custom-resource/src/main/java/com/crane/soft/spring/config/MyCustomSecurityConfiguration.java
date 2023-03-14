package com.crane.soft.spring.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rhine.cloud.security.support.RhineOpaqueTokenIntrospector;
import com.rhine.cloud.security.support.RhineResourceAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class MyCustomSecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
//                        .mvcMatchers("/messages/**").hasAuthority("SCOPE_message.read")
                                .mvcMatchers("/messages/**").hasAuthority("sys_user_add")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
        return http.build();
    }

    /*@Bean
    public OpaqueTokenIntrospector introspector(RestTemplateBuilder builder, OAuth2ResourceServerProperties properties) {
        RestOperations rest = builder
                .basicAuthentication(properties.getOpaquetoken().getClientId(), properties.getOpaquetoken().getClientSecret())
                .setConnectTimeout(Duration.ofSeconds(60))
                .setReadTimeout(Duration.ofSeconds(60))
                .build();

        return new NimbusOpaqueTokenIntrospector(properties.getOpaquetoken().getIntrospectionUri(), rest);
    }*/

    @Bean
    public OpaqueTokenIntrospector introspector(OAuth2AuthorizationService authorizationService) {
        return new RhineOpaqueTokenIntrospector(authorizationService);
    }

    @Bean
    public RhineResourceAuthenticationEntryPoint resourceAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new RhineResourceAuthenticationEntryPoint(objectMapper);
    }
}