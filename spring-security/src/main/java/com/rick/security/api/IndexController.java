package com.rick.security.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Rick
 * @createdAt 2021-10-09 11:31:00
 */
@RestController
public class IndexController {

    @GetMapping("index")
    public String index() {
        return "index";
    }
}
