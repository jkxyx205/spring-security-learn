package com.rick.security.authentication.sms;

import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * @author Rick
 * @createdAt 2021-10-09 22:18:00
 */
@AllArgsConstructor
public class SmsCodeAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String mobile = (String)authentication.getPrincipal();
        String code = (String) authentication.getCredentials();
        // TODO 验证码
        validate(mobile, code);

        UserDetails userDetails = userDetailsService.loadUserByUsername(mobile);
        SmsCodeAuthenticationToken successAuthentication = new SmsCodeAuthenticationToken(userDetails.getUsername(),
                userDetails.getPassword(), userDetails.getAuthorities());

        return successAuthentication;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication == SmsCodeAuthenticationToken.class;
    }

    private void validate(String mobile, String code) {
        if (!"888888".equals(code)) {
            throw new BadCredentialsException("手机验证码不正确！");
        }
    }

}
