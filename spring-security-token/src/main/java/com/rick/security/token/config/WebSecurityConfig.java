package com.rick.security.token.config;

import com.rick.common.http.HttpServletResponseUtils;
import com.rick.common.http.model.ResultUtils;
import com.rick.common.util.JsonUtils;
import com.rick.security.token.filter.TokenAuthenticationFilter;
import com.rick.security.token.util.JWTUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Rick
 * @createdAt 2021-10-16 11:53:00
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled=true, prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> {
            ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl) requests.anyRequest()).authenticated();
        })
                .formLogin()
                // 1. 认证成功后将token响应给前端
                .successHandler((request, response, authentication) -> {
                    String token = JWTUtils.createToken(authentication);
                    HttpServletResponseUtils.write(response, "application/json;charset=UTF-8"
                            , JsonUtils.toJson(ResultUtils.success(token)));
                })
                .and().exceptionHandling().authenticationEntryPoint((request, response, e) -> {
            HttpServletResponseUtils.write(response, "application/json;charset=UTF-8"
                    , JsonUtils.toJson(ResultUtils.exception(403, e.getMessage())));
        })
                .and().exceptionHandling().accessDeniedHandler(new AccessDeniedHandler() {
            @Override
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
                HttpServletResponseUtils.write(response, "application/json;charset=UTF-8"
                        , JsonUtils.toJson(ResultUtils.exception(403, e.getMessage())));
            }
        }).and().addFilterBefore(new TokenAuthenticationFilter(), BasicAuthenticationFilter.class)
                .csrf().disable();

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }
}
