package com.rick.security.config;

import com.rick.common.http.HttpServletResponseUtils;
import com.rick.security.authentication.sms.SmsCodeAuthenticationFilter;
import com.rick.security.authentication.sms.SmsCodeAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.*;

/**
 * @author Rick
 * @createdAt 2021-10-09 14:27:00
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled=true, prePostEnabled = true) // 控制权限注解 配合 @Secured({"ROLE_ADMIN","ROLE_USER2"})使用
@Slf4j
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

        auth.authenticationProvider(new SmsCodeAuthenticationProvider(username -> new User("jkxyx205", "11", AuthorityUtils.commaSeparatedStringToAuthorityList("USER"))));
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
        final LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint = new LoginUrlAuthenticationEntryPoint("/login");

        http.authorizeRequests((requests) -> requests.antMatchers("/public").permitAll()
                .antMatchers(HttpMethod.GET, "/login","/sms/login").permitAll()
                .antMatchers("/admin").hasAnyRole("ADMIN")
                .anyRequest().authenticated())
                .exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
                log.warn("认证异常");
                // 默认就是LoginUrlAuthenticationEntryPoint
                loginUrlAuthenticationEntryPoint.commence(request, response, authException);
        })
                .and()
                .exceptionHandling().accessDeniedHandler((request, response, accessDeniedException) -> {
            // 403 Forbidden 没有授权，执行到此处
            log.warn("已经认证，但是没有权限");
            HttpServletResponseUtils.write(response, "text/plain", "403 Forbidden");
        }).and().csrf().disable(); // csrf会拦截POST请求 https://www.jianshu.com/p/2c275c75c77a;

        final AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        final AuthenticationFailureHandler failureHandler = new SimpleUrlAuthenticationFailureHandler("/login?error");

        http.formLogin()
                // 登录页面的路径
                .loginPage("/login")
                .successHandler((request, response, authentication) -> {
                    log.info("{} 登录成功", authentication.getName());
                    // 跳转到认证前访问到地址(默认就是这个处理器)
                    successHandler.onAuthenticationSuccess(request, response, authentication);
                })
                .failureHandler((request, response, exception) -> {
                    log.error("登录失败 {}", exception.getMessage());
                    // 会将exception放入session中，页面可以通过session获取异常
                    failureHandler.onAuthenticationFailure(request, response, exception);
//                    response.sendRedirect("/login?error=" + exception.getMessage());
                })
                .and()
                .logout()
                .logoutSuccessHandler((request, response, authentication) -> {
                    log.info("{} 退出登录", authentication.getName());
                    response.sendRedirect("/login");
                });

        http.httpBasic();

        http.addFilterBefore(new SmsCodeAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //解决static下静态资源被拦截的问题
        web.ignoring().antMatchers( "/css/**", "/js/**", "/img/**", "/plugins/**", "/favicon.ico");
    }
}
