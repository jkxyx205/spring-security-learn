package com.rick.security.oauth2.server;

import com.rick.security.oauth2.server.util.TokenGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Rick
 * @createdAt 2021-10-15 19:25:00
 */
@SpringBootTest
public class TokenGeneratorTest {

    @Autowired
    private TokenGenerator tokenGenerator;

    @Test
    public void testCreateToken() {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken
                = new UsernamePasswordAuthenticationToken("rick", "123456"
                , AuthorityUtils.commaSeparatedStringToAuthorityList("ADMIN, p1, p2"));
        OAuth2AccessToken token = tokenGenerator.createToken(usernamePasswordAuthenticationToken);
        System.out.println(token.getExpiration());
        System.out.println(token);
    }

    @Test
    public void testRefresh() {
        String accessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzIl0sInVzZXJfbmFtZSI6InJpY2siLCJzY29wZSI6WyJhbGwiXSwiaGVsbG8iOiJ3b3JsZCIsImV4cCI6MTYzNDMwMzQ5NiwiYXV0aG9yaXRpZXMiOlsicDEiLCJwMiIsIkFETUlOIl0sImp0aSI6IlNjZlM3SHUzRU5nVi1RcDNBa091Tno5TU9VcyIsImNsaWVudF9pZCI6ImMifQ.ztgs8zpS1VUVB04QQ4gTrySwMMr5FexX5jLVfuTRykg";
        OAuth2AccessToken token = tokenGenerator.refresh(accessToken);
        System.out.println(token.getValue().equals(accessToken));
        System.out.println(token.getValue());
    }
}
