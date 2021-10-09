package com.rick.security.authentication.sms;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * @author Rick
 * @createdAt 2021-10-09 22:13:00
 */
public class SmsCodeAuthenticationToken extends AbstractAuthenticationToken {

    private String mobile;

    private String code;

    public SmsCodeAuthenticationToken(String mobile, String code) {
        super(null);
        this.mobile = mobile;
        this.code = code;
        setAuthenticated(false);
    }

    public SmsCodeAuthenticationToken(String mobile, String code,
                                               Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.mobile = mobile;
        this.code = code;
        super.setAuthenticated(true); // must use super, as we override
    }

    @Override
    public Object getCredentials() {
        return this.code;
    }

    @Override
    public Object getPrincipal() {
        return this.mobile;
    }
}
