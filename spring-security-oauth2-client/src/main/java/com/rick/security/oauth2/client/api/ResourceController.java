package com.rick.security.oauth2.client.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Rick
 * @createdAt 2021-10-10 09:55:00
 */
@RestController
public class ResourceController {

    /**
     * 通过token，可以访问github上的其他资源
     * curl -X GET \
     *   https://api.github.com/user \
     *   -H 'Authorization: Bearer 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' \
     * @param authorizedClient
     * @return
     */
    @GetMapping(value = {"index", "/"})
    public String index(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return "index token = " + authorizedClient.getAccessToken().getTokenValue();
    }

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
