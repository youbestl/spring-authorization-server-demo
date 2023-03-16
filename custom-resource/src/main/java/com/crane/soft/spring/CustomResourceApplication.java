package com.crane.soft.spring;

import com.rhine.cloud.security.annotation.EnableRhineResourceServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * @author DL
 */
@SpringBootApplication
@EnableRhineResourceServer
public class CustomResourceApplication {
    public static void main(String[] args) {
        SpringApplication.run(CustomResourceApplication.class, args);
    }
}