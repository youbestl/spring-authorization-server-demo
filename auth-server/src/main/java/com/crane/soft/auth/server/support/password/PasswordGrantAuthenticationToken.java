package com.crane.soft.auth.server.support.password;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

/**
 * @author DL
 */
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    /**
     * Sub-class constructor.
     *
     * @param clientPrincipal      the authenticated client principal
     * @param additionalParameters the additional parameters
     */
    protected PasswordGrantAuthenticationToken(Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
    }
}
