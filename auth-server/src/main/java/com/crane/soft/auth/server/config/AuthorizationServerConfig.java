/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.crane.soft.auth.server.config;

import com.crane.soft.auth.server.authentication.DeviceClientAuthenticationProvider;
import com.crane.soft.auth.server.constants.OAuth2Constants;
import com.crane.soft.auth.server.controller.authentication.DeviceClientAuthenticationConverter;
import com.crane.soft.auth.server.federation.FederatedIdentityAuthenticationSuccessHandler;
import com.crane.soft.auth.server.federation.FederatedIdentityIdTokenCustomizer;
import com.crane.soft.auth.server.jose.Jwks;
import com.crane.soft.auth.server.support.password.PasswordGrantAuthenticationConvert;
import com.crane.soft.auth.server.support.password.PasswordGrantAuthenticationProvider;
import com.crane.soft.auth.server.support.sms.SmsGrantAuthenticationConvert;
import com.crane.soft.auth.server.support.sms.SmsGrantAuthenticationProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.UUID;

/**
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Steve Riesenberg
 * @since 1.1
 */
@Configuration
public class AuthorizationServerConfig {
    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    @Bean
    @Order(2)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http, RegisteredClientRepository registeredClientRepository,
			AuthorizationServerSettings authorizationServerSettings,
			OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<?> tokenGenerator) throws Exception {
        //为OAuth 2.0授权服务器设置默认的安全配置
		//OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();
		RequestMatcher endpointsMatcher = authorizationServerConfigurer
				.getEndpointsMatcher();
		http
				.securityMatcher(endpointsMatcher)
				.authorizeHttpRequests(authorize ->
						authorize.requestMatchers("/oauth2/token", "/error").permitAll()
								.anyRequest().authenticated()
				)
				.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
				.apply(authorizationServerConfigurer);

        // 设备授权码模式相关
        DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
                new DeviceClientAuthenticationConverter(
                        authorizationServerSettings.getDeviceAuthorizationEndpoint());
        DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
                new DeviceClientAuthenticationProvider(registeredClientRepository);

        // @formatter:off
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
				deviceAuthorizationEndpoint.verificationUri("/activate")
			)
			.deviceVerificationEndpoint(deviceVerificationEndpoint ->
				deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
			)
			.clientAuthentication(clientAuthentication ->
				clientAuthentication
					.authenticationConverter(deviceClientAuthenticationConverter)
					.authenticationProvider(deviceClientAuthenticationProvider)
			)// 自定义密码模式
			.authorizationEndpoint(authorizationEndpoint ->
				authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
				.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint.accessTokenRequestConverter(
								new PasswordGrantAuthenticationConvert())
								.authenticationProvider(
										new PasswordGrantAuthenticationProvider(authorizationService, tokenGenerator)))
				//短信验证码模式登录
				.tokenEndpoint(tokenEndpoint ->
						tokenEndpoint.accessTokenRequestConverter(
										new SmsGrantAuthenticationConvert())
								.authenticationProvider(
										new SmsGrantAuthenticationProvider(authorizationService, tokenGenerator)))
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		// @formatter:on

        // @formatter:off
		http
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"), // 登录表单提交地址
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			.oauth2ResourceServer(oauth2ResourceServer ->
				oauth2ResourceServer.jwt(Customizer.withDefaults())); // 使用jwt处理toke
		// @formatter:on
        return http.build();
    }
    // @formatter:off

	/**
     * @param jdbcTemplate
     * @return
     */
	@Bean
	public JdbcRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {

		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client") // client_id
				.clientSecret("$2a$10$XHMdPVX.NMPlNwkMu31tKurBms6SrhUegjxW1h8iCWFmhxMatvs4q") // client_secret {noop} secret表示明文传输
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) //客户端身份验证方法
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) //授权码模式
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 刷新令牌
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // 客户端模式
				.redirectUri("http://127.0.0.1:8081/login/oauth2/code/messaging-client-oidc") //回调地址
				.redirectUri("http://127.0.0.1:8081/authorized") // 回调地址
				//.redirectUri("https://www.baidu.com/") // 这里修改为百度方便查看授权码code
				.postLogoutRedirectUri("http://127.0.0.1:8081/logged-out") // 退出登录回调地址
				.scope(OidcScopes.OPENID) // 授权范围 openid
				.scope(OidcScopes.PROFILE) // profile
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // 客户端设置
				.build();

		RegisteredClient deviceClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("device-messaging-client")
				.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.scope("message.read")
				.scope("message.write")
				.build();

		//密码模式
		RegisteredClient registeredPasswordClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-password-client") // client_id
				.clientSecret("$2a$10$XHMdPVX.NMPlNwkMu31tKurBms6SrhUegjxW1h8iCWFmhxMatvs4q") // client_secret {noop} secret表示明文传输
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) //客户端身份验证方法
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) //授权码模式
				.authorizationGrantType(AuthorizationGrantType.PASSWORD) //自定义密码模式
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 刷新令牌
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // 客户端模式
				.redirectUri("http://127.0.0.1:8081/login/oauth2/code/messaging-client-oidc") //回调地址
				.redirectUri("http://127.0.0.1:8081/authorized") // 回调地址
				//.redirectUri("https://www.baidu.com/") // 这里修改为百度方便查看授权码code
				.postLogoutRedirectUri("http://127.0.0.1:8081/logged-out") // 退出登录回调地址
				.scope(OidcScopes.OPENID) // 授权范围 openid
				.scope(OidcScopes.PROFILE) // profile
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // 客户端设置
				.build();


		RegisteredClient registeredSmsClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-sms-client") // client_id
				.clientSecret("$2a$10$XHMdPVX.NMPlNwkMu31tKurBms6SrhUegjxW1h8iCWFmhxMatvs4q") // client_secret {noop} secret表示明文传输
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) //客户端身份验证方法
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE) //授权码模式
				.authorizationGrantType(AuthorizationGrantType.PASSWORD) //自定义密码模式
				.authorizationGrantType(new AuthorizationGrantType(OAuth2Constants.GRANT_TYPE_MOBILE)) //短信验证码登录
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN) // 刷新令牌
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS) // 客户端模式
				.redirectUri("http://127.0.0.1:8081/login/oauth2/code/messaging-client-oidc") //回调地址
				.redirectUri("http://127.0.0.1:8081/authorized") // 回调地址
				//.redirectUri("https://www.baidu.com/") // 这里修改为百度方便查看授权码code
				.postLogoutRedirectUri("http://127.0.0.1:8081/logged-out") // 退出登录回调地址
				.scope(OidcScopes.OPENID) // 授权范围 openid
				.scope(OidcScopes.PROFILE) // profile
				.scope("message.read")
				.scope("message.write")
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()) // 客户端设置
				.build();


		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);

        // 注册客户端信息 如果Mysql 数据库模式则只需运行一次即可，不然会报冲突的错
		// registeredClientRepository.save(registeredClient); // 普通客户端
        // registeredClientRepository.save(deviceClient); // 设备客户端
		// registeredClientRepository.save(registeredPasswordClient); // 密码模式客户端
		// registeredClientRepository.save(registeredSmsClient); // 短信验证码登录

		return registeredClientRepository;
	}
	// @formatter:on

    /**
     * 对应 oauth2_authorization 表
     *
     * @param jdbcTemplate
     * @param registeredClientRepository
     * @return
     */
    /*@Bean
    public JdbcOAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                               RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }*/

    /**
     * 对应 oauth2_authorization_consent 表
     *
     * @param jdbcTemplate
     * @param registeredClientRepository
     * @return
     */
    @Bean
    public JdbcOAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                                                                             RegisteredClientRepository registeredClientRepository) {
        // Will be used by the ConsentController
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }


	@Bean
	public OAuth2TokenGenerator<?> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

    /**
	 * 自定义生成id_token的规则
     *
     * @return
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> idTokenCustomizer() {
        return new FederatedIdentityIdTokenCustomizer();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    private AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new FederatedIdentityAuthenticationSuccessHandler();
    }


	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

    /**
     * 默认使用内嵌H2数据库进行存储
     *
     * @return
     */
    //@Bean
    public EmbeddedDatabase embeddedDatabase() {
        // @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
    }

}
