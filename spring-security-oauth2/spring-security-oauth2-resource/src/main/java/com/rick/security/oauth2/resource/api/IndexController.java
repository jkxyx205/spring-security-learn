package com.rick.security.oauth2.resource.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Rick
 * @createdAt 2021-10-14 17:47:00
 */
@RestController
public class IndexController {

    @GetMapping
    public String index() {
        return "index";
    }

    @GetMapping("admin")
    public String admin(Authentication authentication, @RequestParam("access_token") String accessToken) {
        return authentication.toString();
    }

    @GetMapping("p1")
    @PreAuthorize("hasRole('p1')")
    public String p1(Authentication authentication, @RequestParam("access_token") String accessToken) {
        Jwt jwt = JwtHelper.decode(accessToken);
        return jwt.getClaims();
    }
}
