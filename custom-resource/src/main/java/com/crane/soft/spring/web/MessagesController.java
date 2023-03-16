package com.crane.soft.spring.web;

import cn.hutool.json.JSONUtil;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @author DL
 */
@RestController
public class MessagesController {

    @GetMapping("/messages")
    public String[] getMessages() {
        return new String[]{"Message 1", "Message 2", "Message 3"};
    }

    @PreAuthorize("@pms.hasAuthority('sys_user_edit')")
    @GetMapping("/getUserInfo")
    public String getUserInfo() {

        Map<String, String> map = new HashMap<>();
        map.put("username", "zhangsan");
        map.put("age", "18");
        map.put("address", "beijign");

        return JSONUtil.toJsonStr(map);
    }
}
