package com.rick.security.oauth2.client.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * @author Rick
 * @createdAt 2021-10-10 09:54:00
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled=true, prePostEnabled = true)
@Slf4j
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        final AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        http
            .authorizeRequests(a -> a
                    .antMatchers("/public", "/error", "/webjars/**").permitAll()
                    .antMatchers("/admin").hasAnyRole("admin")
                    .anyRequest().authenticated()
            )
            .exceptionHandling(e -> e
                            .authenticationEntryPoint((request, response, e1) -> {
                                log.error("认证异常：{}", e1.getMessage());
                                response.sendRedirect("oauth2/authorization/github");
                            })
            )
            .oauth2Login().successHandler(((request, response, authentication) -> {
                log.error("认证成功");
                OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken)authentication;
                log.info("{} 在github上的信息是：{}", oAuth2AuthenticationToken.getPrincipal().getName(),
                        oAuth2AuthenticationToken);
                successHandler.onAuthenticationSuccess(request, response, authentication);
            }));
    }
}