package com.rick.security.oauth2.resourceserver.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

/**
 * @author Rick
 * @createdAt 2021-09-24 16:33:00
 */
@EnableWebSecurity
public class ResourceServerConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 允许参数access_token
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setAllowUriQueryParameter(true);

        http
            .authorizeRequests(a -> a
                    .antMatchers("/public", "/error", "/webjars/**").permitAll()
                    .antMatchers("/admin").hasAnyRole("admin")
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer()
                .bearerTokenResolver(resolver)
            .jwt();
    }

}
