package com.crane.soft.auth.server.support.sms;

import com.crane.soft.auth.server.constants.OAuth2Constants;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

/**
 * @author DL
 */
public class SmsGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

    /**
     * Sub-class constructor.
     *
     * @param clientPrincipal      the authenticated client principal
     * @param additionalParameters the additional parameters
     */
    protected SmsGrantAuthenticationToken(Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType(OAuth2Constants.GRANT_TYPE_MOBILE), clientPrincipal, additionalParameters);
    }
}
