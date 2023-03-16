package com.crane.soft.spring.config;

//@EnableWebSecurity
//@Configuration(proxyBeanMethods = false)
//@RequiredArgsConstructor
public class MyCustomSecurityConfiguration {

//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
////                        .mvcMatchers("/messages/**").hasAuthority("SCOPE_message.read")
//                                .mvcMatchers("/messages/**").hasAuthority("sys_user_add")
//                        .anyRequest().authenticated()
//                )
//                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
//        return http.build();
//    }

    /*@Bean
    public OpaqueTokenIntrospector introspector(RestTemplateBuilder builder, OAuth2ResourceServerProperties properties) {
        RestOperations rest = builder
                .basicAuthentication(properties.getOpaquetoken().getClientId(), properties.getOpaquetoken().getClientSecret())
                .setConnectTimeout(Duration.ofSeconds(60))
                .setReadTimeout(Duration.ofSeconds(60))
                .build();

        return new NimbusOpaqueTokenIntrospector(properties.getOpaquetoken().getIntrospectionUri(), rest);
    }*/

}