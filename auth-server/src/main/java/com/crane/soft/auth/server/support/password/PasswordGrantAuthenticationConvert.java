package com.crane.soft.auth.server.support.password;

import cn.hutool.core.util.StrUtil;
import com.crane.soft.auth.server.support.OAuth2Utils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

/**
 * @author DL
 */
public class PasswordGrantAuthenticationConvert implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {

        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = OAuth2Utils.getParameters(request);
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        // 校验用户名密码
        if (StrUtil.isBlank(username) ||
                parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
            throw new OAuth2AuthenticationException("用户名不能为空！");
        }
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (StrUtil.isBlank(password) ||
                parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
            throw new OAuth2AuthenticationException("密码不能为空！");
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        // 从 request 中提取的参数，排除掉 grant_type、client_id、code等字段参数
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals(OAuth2ParameterNames.CODE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        return new PasswordGrantAuthenticationToken(clientPrincipal, additionalParameters);
    }

}
