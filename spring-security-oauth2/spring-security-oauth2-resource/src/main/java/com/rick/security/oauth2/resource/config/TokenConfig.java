package com.rick.security.oauth2.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

/**
 * @author Rick
 * @createdAt 2021-10-14 20:41:00
 */
//@Configuration
public class TokenConfig {

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
}
