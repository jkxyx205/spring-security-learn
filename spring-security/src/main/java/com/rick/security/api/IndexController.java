package com.rick.security.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Rick
 * @createdAt 2021-10-09 11:31:00
 */
@RestController
public class IndexController {

    @GetMapping(value = {"index", "/"})
    public String index() {
        return "index";
    }

    @GetMapping("public")
    public String publicFun() {
        return "public";
    }

    @GetMapping("admin")
    public String admin() {
        return "admin";
    }

    @PreAuthorize("hasAnyRole('USER')")
    @GetMapping("user")
    public String user() {
        return "user";
    }
}
