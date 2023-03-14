package com.crane.soft.spring.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

/**
 * @author DL
 */
@Slf4j
@Component
public class ConsumerAuthorizationDeniedEvent implements ApplicationListener<AuthorizationDeniedEvent> {
    @Override
    public void onApplicationEvent(AuthorizationDeniedEvent event) {
        Authentication authentication = (Authentication) event.getAuthentication().get();
        log.info("权限验证失败：{}", authentication.getAuthorities());
    }
}
