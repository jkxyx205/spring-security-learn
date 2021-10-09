package com.rick.security.config;

import com.rick.common.http.HttpServletResponseUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author Rick
 * @createdAt 2021-10-09 14:27:00
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 自定义用户信息并授权
     * @return
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("rick")
                .password(passwordEncoder.encode("123456"))
                .roles("ADMIN")
                .and()
                .withUser("john")
                .password(passwordEncoder.encode("123456"))
                .roles("USER");

    }

//    @Bean
//    @Override
//    public UserDetailsService userDetailsService() {
//        //Admin Role
//        UserDetails theUser = User.withUsername("rick")
//                .password(passwordEncoder.encode("123456"))
//                .roles("ADMIN").build();
//
//        //User Role
//        UserDetails theManager = User.withUsername("john")
//                .password(passwordEncoder.encode("123456"))
//                .roles("USER").build();
//
//
//        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
//
//        userDetailsManager.createUser(theUser);
//        userDetailsManager.createUser(theManager);
//        return userDetailsManager;
//    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests((requests) -> requests.antMatchers("/public").permitAll()
                .antMatchers("/admin").hasAnyRole("ADMIN")
                .anyRequest().authenticated())
                .exceptionHandling().accessDeniedHandler((request, response, accessDeniedException) -> {
                    // 403 Forbidden 没有授权，执行到此处
            HttpServletResponseUtils.write(response, "text/plain", "403 Forbidden");
        });
        http.formLogin();
        http.httpBasic();
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .antMatchers("/static/**");
    }
}
