package com.rick.security.oauth2.server.util;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Objects;

/**
 * All rights Reserved, Designed By www.xhope.top
 *
 * @version V1.0
 * @Description: (用一句话描述该文件做什么)
 * @author: Rick.Xu
 * @date: 9/8/19 1:36 PM
 * @Copyright: 2019 www.yodean.com. All rights reserved.
 */
@Component
public class TokenGenerator {

    @Autowired
    @Qualifier("tokenServices")
    private AuthorizationServerTokenServices authorizationServerTokenServices;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Autowired
    private TokenStore tokenStore;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    private static final String ACCESS_TO_REFRESH = "access_to_refresh:";

    /**
     * 表单验证完成后创建token
     * @param authentication
     * @return
     */
    public OAuth2AccessToken createToken(Authentication authentication) {
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId("c");
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = (UsernamePasswordAuthenticationToken) authentication;

        TokenRequest tokenRequest = tokenRequest();

        OAuth2Request oAuth2Request = tokenRequest.createOAuth2Request(clientDetails);

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, usernamePasswordAuthenticationToken);

        OAuth2AccessToken token = authorizationServerTokenServices.createAccessToken(oAuth2Authentication);

        return token;
    }

    /**
     * 刷新token
     * @param accessToken
     * @return
     */
    public OAuth2AccessToken refresh(String accessToken) {
        OAuth2AccessToken _accessToken = tokenStore.readAccessToken(accessToken);
        if (Objects.nonNull(_accessToken) && !_accessToken.isExpired()) {
            return _accessToken;
        }

        String refreshToken = stringRedisTemplate.opsForValue().get(ACCESS_TO_REFRESH + accessToken);
        return authorizationServerTokenServices.refreshAccessToken(refreshToken, tokenRequest());
    }


    private TokenRequest tokenRequest() {
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId("c");

        TokenRequest tokenRequest = new TokenRequest(Collections.emptyMap(),
                clientDetails.getClientId(),
                clientDetails.getScope(),
                "all");

        return tokenRequest;
    }
}
