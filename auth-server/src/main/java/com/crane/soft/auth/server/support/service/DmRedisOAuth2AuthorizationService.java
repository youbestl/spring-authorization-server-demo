package com.crane.soft.auth.server.support.service;

import cn.hutool.core.lang.Assert;
import com.crane.soft.auth.server.support.token.CustomRefreshToken;
import jakarta.annotation.Resource;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * 拓展 token 存储方式 redis
 *
 * @author DL
 */
@Component
public class DmRedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final Integer CACHE_TIME_OUT = 10;

    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");

        if (isContainState(authorization)) {
            String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
            redisTemplate.opsForValue().set(generateKey(OAuth2ParameterNames.STATE, state), authorization, CACHE_TIME_OUT, TimeUnit.MINUTES);
        }

        if (isContainCode(authorization)) {
            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization
                    .getToken(OAuth2AuthorizationCode.class);
            OAuth2AuthorizationCode authorizationCodeToken = authorizationCode.getToken();
            //计算还有多久过期
            long between = ChronoUnit.MINUTES.between(authorizationCodeToken.getIssuedAt(),
                    authorizationCodeToken.getExpiresAt());
            redisTemplate.opsForValue()
                    .set(generateKey(OAuth2ParameterNames.CODE, authorizationCodeToken.getTokenValue()), authorization,
                            between, TimeUnit.MINUTES);
        }

        if (isContainRefreshToken(authorization)) {
            OAuth2RefreshToken refreshToken = authorization.getToken(CustomRefreshToken.class).getToken();
            long between = ChronoUnit.SECONDS.between(refreshToken.getIssuedAt(), refreshToken.getExpiresAt());
            redisTemplate.opsForValue()
                    .set(generateKey(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken.getTokenValue()), authorization, between,
                            TimeUnit.SECONDS);
        }

        if (isContainAccessToken(authorization)) {
            OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
            long between = ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt());
            redisTemplate.opsForValue()
                    .set(generateKey(OAuth2ParameterNames.ACCESS_TOKEN, accessToken.getTokenValue()), authorization, between,
                            TimeUnit.SECONDS);
        }

        if (isContainIdToken(authorization)) {
            OAuth2Authorization.Token<OidcIdToken> authorizedIdToken = authorization.getToken(OidcIdToken.class);
            OidcIdToken oidcIdToken = authorizedIdToken.getToken();
            long between = ChronoUnit.SECONDS.between(oidcIdToken.getIssuedAt(), oidcIdToken.getExpiresAt());
            redisTemplate.opsForValue()
                    .set(generateKey(OidcParameterNames.ID_TOKEN, oidcIdToken.getTokenValue()), authorization, between,
                            TimeUnit.SECONDS);
        }

    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        List<String> keys = new ArrayList<>();
        if (isContainState(authorization)) {
            String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
            keys.add(generateKey(OAuth2ParameterNames.STATE, state));
        }
        if (isContainCode(authorization)) {
            OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode = authorization
                    .getToken(OAuth2AuthorizationCode.class);
            OAuth2AuthorizationCode authorizationCodeToken = authorizationCode.getToken();
            keys.add(generateKey(OAuth2ParameterNames.CODE, authorizationCodeToken.getTokenValue()));
        }
        if (isContainRefreshToken(authorization)) {
            OAuth2RefreshToken refreshToken = authorization.getRefreshToken().getToken();
            keys.add(generateKey(OAuth2ParameterNames.REFRESH_TOKEN, refreshToken.getTokenValue()));
        }
        if (isContainAccessToken(authorization)) {
            OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
            keys.add(generateKey(OAuth2ParameterNames.ACCESS_TOKEN, accessToken.getTokenValue()));
        }

        if (isContainIdToken(authorization)) {
            OAuth2Authorization.Token<OidcIdToken> authorizedIdToken = authorization.getToken(OidcIdToken.class);
            keys.add(generateKey(OidcParameterNames.ID_TOKEN, authorizedIdToken.getToken().getTokenValue()));
        }

        //批量删除key
        redisTemplate.delete(keys);
    }

    private boolean isContainIdToken(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OidcIdToken> authorizedIdToken = authorization.getToken(OidcIdToken.class);
        return Objects.nonNull(authorizedIdToken);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return null;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.notEmpty(token, "token cannot be empty");
        Assert.notNull(tokenType, "tokenType cannot be null");

        return (OAuth2Authorization) redisTemplate.opsForValue().get(generateKey(tokenType.getValue(), token));
    }

    private String generateKey(String type, String id) {
        return "token::" + type + "::" + id;
    }

    private boolean isContainState(OAuth2Authorization authorization) {
        return Objects.nonNull(authorization.getAttribute(OAuth2ParameterNames.STATE));
    }

    private boolean isContainCode(OAuth2Authorization authorization) {
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCodeToken
                = authorization.getToken(OAuth2AuthorizationCode.class);
        return Objects.nonNull(authorizationCodeToken);
    }

    private boolean isContainRefreshToken(OAuth2Authorization authorization) {
        return Objects.nonNull(authorization.getToken(CustomRefreshToken.class));
    }

    private boolean isContainAccessToken(OAuth2Authorization authorization) {
        return Objects.nonNull(authorization.getAccessToken());
    }

}
