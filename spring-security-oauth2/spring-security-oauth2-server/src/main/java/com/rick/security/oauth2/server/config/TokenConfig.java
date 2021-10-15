package com.rick.security.oauth2.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.token.*;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Rick
 * @createdAt 2021-10-14 20:41:00
 */
@Configuration
public class TokenConfig {

    private String SIGNING_KEY = "uaa123";

//    @Bean
//    public TokenStore tokenStore() {
//        //使用内存存储令牌（普通令牌）
////        return new InMemoryTokenStore();
//        return new JwtTokenStore(accessTokenConverter());
//    }

    @Bean
    public TokenStore tokenStore(RedisConnectionFactory redisConnectionFactory) {
        return new RedisTokenStore(redisConnectionFactory);
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
    public TokenEnhancer tokenEnhancer() {
        return (oAuth2AccessToken, oAuth2Authentication) -> {
            Map<String, Object> info = new HashMap<>();
            info.put("hello", "world");
            ((DefaultOAuth2AccessToken) oAuth2AccessToken).setAdditionalInformation(info);
            return oAuth2AccessToken;
        };
    }

}
