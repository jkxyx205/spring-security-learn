package com.rick.security.oauth2.api;

import org.springframework.web.bind.annotation.GetMapping;
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
}
