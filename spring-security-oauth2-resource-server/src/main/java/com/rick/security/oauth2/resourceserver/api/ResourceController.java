package com.rick.security.oauth2.resourceserver.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Rick
 * @createdAt 2021-10-10 09:55:00
 */
@RestController
public class ResourceController {

    /**
     * 403没有访问权限
     * @return
     */
    @GetMapping(value = "admin")
    public String admin() {
        return "admin";
    }

    @PreAuthorize("hasAnyAuthority('ROLE_USER, SCOPE_user')")
    @GetMapping(value = "user")
    public String user() {
        return "user";
    }

    /**
     * 不需要认证就能访问
     * @return
     */
    @GetMapping(value = "public")
    public String publicFun() {
        return "public";
    }
}
