package com.rick.security.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.*;

/**
 * @author Rick
 * @createdAt 2021-10-14 20:41:00
 */
@Configuration
public class SecurityConfig {

    private String SIGNING_KEY = "uaa123";

    @Bean
    public TokenStore tokenStore() {
        //使用内存存储令牌（普通令牌）
//        return new InMemoryTokenStore();
        return new JwtTokenStore(accessTokenConverter());
    }

    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(SIGNING_KEY); //对称秘钥，资源服务器使用该秘钥来验证
        return converter;
    }

    // 令牌管理服务
    @Bean("tokenServices")
    public AuthorizationServerTokenServices tokenService(ClientDetailsService clientDetailsService, TokenStore tokenStore) {
        DefaultTokenServices service=new DefaultTokenServices();
        service.setClientDetailsService(clientDetailsService);//客户端详情服务
        service.setSupportRefreshToken(true);//支持刷新令牌
        service.setTokenStore(tokenStore);//令牌存储策略

        // 令牌增强，支持Jwt令牌
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        // 注意顺序accessTokenConverter在最后
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(tokenEnhancer(), accessTokenConverter()));
        service.setTokenEnhancer(tokenEnhancerChain);

        service.setReuseRefreshToken(false); // 只对"存储"的有效，jwt_stoken无效
        service.setAccessTokenValiditySeconds(60); // 令牌默认有效期2小时
        service.setRefreshTokenValiditySeconds(259200); // 刷新令牌默认有效期3天
        return service;
    }

    @Bean
    public AuthenticationManager authenticationManager(PasswordEncoder passwordEncoder) {
        List<AuthenticationProvider> providers = new ArrayList<>();
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService(passwordEncoder));
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        providers.add(daoAuthenticationProvider);
        return new ProviderManager(providers);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public TokenEnhancer tokenEnhancer() {
        return (oAuth2AccessToken, oAuth2Authentication) -> {
            Map<String, Object> info = new HashMap<>();
            info.put("hello", "world");
            ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(info);
            return oAuth2AccessToken;
        };
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        //Admin Role
        UserDetails theUser = User.withUsername("rick")
                .password(passwordEncoder.encode("123456"))
                .roles("ADMIN", "p1").build();
        //User Role
        UserDetails theManager = User.withUsername("john")
                .password(passwordEncoder.encode("123456"))
                .roles("USER").build();
        InMemoryUserDetailsManager userDetailsManager = new InMemoryUserDetailsManager();
        userDetailsManager.createUser(theUser);
        userDetailsManager.createUser(theManager);
        return userDetailsManager;
    }
}
