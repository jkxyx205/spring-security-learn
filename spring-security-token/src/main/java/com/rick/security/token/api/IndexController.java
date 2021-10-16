package com.rick.security.token.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Rick
 * @createdAt 2021-10-16 11:58:00
 */
@RestController
public class IndexController {

    @GetMapping
    public String index() {
        return "index";
    }

    @GetMapping("admin")
    public String admin(Authentication authentication) {
        return "admin ==> ";
    }

    @GetMapping("p1")
    @PreAuthorize("hasRole('p1')")
    public String p1(Authentication authentication) {
        return authentication.getPrincipal().toString();
    }
}