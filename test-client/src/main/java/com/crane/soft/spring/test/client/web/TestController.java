package com.crane.soft.spring.test.client.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author DL
 */
@RestController
public class TestController {
    @GetMapping("/")
    public void getAuthorization(HttpServletResponse response) throws IOException {
        String url =
                String.format("http://127.0.0.1:9000/my/authorize?response_type=code&client_id=%s&scope=message.read message.write openid&redirect_uri=%s",
                        "test-client", "http://127.0.0.1:8081/callback");
        response.sendRedirect(url);
    }

    @GetMapping("/index")
    public void getAuthorizationIndex(HttpServletResponse response) throws IOException {
        String url =
                String.format("http://127.0.0.1:9000/oauth2/authorize?response_type=code&client_id=%s&scope=server&redirect_uri=%s",
                        "test", "http://127.0.0.1:8081/callback");
        response.sendRedirect(url);
    }

    @GetMapping("/callback")
    public String callback(String code) {
        return code;
    }
}
