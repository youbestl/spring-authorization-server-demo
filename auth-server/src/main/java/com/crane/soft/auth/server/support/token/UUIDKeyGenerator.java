package com.crane.soft.auth.server.support.token;

import org.springframework.security.crypto.keygen.StringKeyGenerator;

import java.util.UUID;

/**
 * @author DL
 */
public class UUIDKeyGenerator implements StringKeyGenerator {
    @Override
    public String generateKey() {
        return UUID.randomUUID().toString().toLowerCase();
    }
}
