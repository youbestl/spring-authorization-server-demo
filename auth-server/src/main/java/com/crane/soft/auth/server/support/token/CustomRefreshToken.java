package com.crane.soft.auth.server.support.token;

import org.springframework.security.oauth2.core.OAuth2RefreshToken;

import java.time.Instant;
import java.util.Set;

/**
 * @author DL
 */
public class CustomRefreshToken extends OAuth2RefreshToken {

    private final Set<String> scopes;

    public CustomRefreshToken(String tokenValue, Instant issuedAt, Set<String> scopes) {
        super(tokenValue, issuedAt);
        this.scopes = scopes;
    }

    public CustomRefreshToken(String tokenValue, Instant issuedAt, Instant expiresAt, Set<String> scopes) {
        super(tokenValue, issuedAt, expiresAt);
        this.scopes = scopes;
    }

    public Set<String> getScopes() {
        return scopes;
    }
}
