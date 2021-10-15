package com.rick.security.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;

/**
 * @author Rick
 * @createdAt 2021-10-14 16:40:00
 */
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled=true, prePostEnabled = true)
public class ResourceServer extends ResourceServerConfigurerAdapter {

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        // 资源id
        resources.resourceId("res")
                .stateless(true)
                .accessDeniedHandler((request, response, e) -> {
                    response.getWriter().write(e.getMessage());
                });
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest()).authenticated();

    }
}
