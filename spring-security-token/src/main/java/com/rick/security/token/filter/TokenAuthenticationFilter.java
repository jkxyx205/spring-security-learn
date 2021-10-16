package com.rick.security.token.filter;

import com.rick.common.http.HttpServletResponseUtils;
import com.rick.common.http.model.ResultUtils;
import com.rick.common.util.JsonUtils;
import com.rick.security.token.util.JWTUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Rick
 * @createdAt 2021-10-16 11:48:00
 */
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        String accessToken = request.getParameter("access_token");
        if (StringUtils.isBlank(accessToken)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            Authentication authentication = JWTUtils.toAuthentication(accessToken);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            chain.doFilter(request, response);
        } catch (Exception e) {
            HttpServletResponseUtils.write(response, "application/json;charset=UTF-8"
                    , JsonUtils.toJson(ResultUtils.exception(403, e.getMessage())));
        }
    }
}
