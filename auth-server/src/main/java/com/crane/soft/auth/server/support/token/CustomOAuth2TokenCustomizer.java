package com.crane.soft.auth.server.support.token;

import com.crane.soft.auth.server.constants.OAuth2Constants;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * @author DL
 */
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<OAuth2TokenClaimsContext> {
    /**
     * Customize the OAuth 2.0 Token attributes.
     *
     * @param context the context containing the OAuth 2.0 Token attributes
     */
    @Override
    public void customize(OAuth2TokenClaimsContext context) {
        OAuth2TokenClaimsSet.Builder claims = context.getClaims();
        String clientId = context.getAuthorizationGrant().getName();
        claims.claim(OAuth2Constants.CLIENT_ID, clientId);
        claims.claim(OAuth2Constants.ACTIVE, Boolean.TRUE);
        // 客户端模式不返回具体用户信息
        if (OAuth2Constants.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType().getValue())) {
            return;
        }
        claims.claim(OAuth2Constants.DETAILS_USERNAME, "user");
        claims.claim("age", "18");

    }
}
