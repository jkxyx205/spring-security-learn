# 集成github第三方登录

## 添加依赖 `build.gradle`

```
    implementation "org.springframework.boot:spring-boot-starter-oauth2-client"
    implementation 'org.springframework.boot:spring-boot-starter-web'
```

## 配置文件 `application.yml`

```yml
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: xxx
            client-secret: xxx
            authorization-grant-type: authorization_code
            # /login/oauth2/code/ 固定格式
            redirect-uri: "http://localhost:8080/login/oauth2/code/github"
            # 只有一个权限就是user
            scope: user
        provider:
          github:
            authorization-uri: https://github.com/login/oauth/authorize
            token-uri: https://github.com/login/oauth/access_token

```
前往[OAuth Apps](https://github.com/settings/developers)配置github client信息
## 配置类 `OAuth2ClientSecurityConfig.java`

```java
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled=true, prePostEnabled = true)
@Slf4j
public class OAuth2ClientSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(a -> a
                        .antMatchers("/public", "/error", "/webjars/**").permitAll()
                        .antMatchers("/admin").hasAnyRole("admin")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(e -> e
                                .authenticationEntryPoint((request, response, e1) -> {
                                    log.error("认证异常：{}", e1.getMessage());
                                    response.sendRedirect("oauth2/authorization/github");
                                })
                )
                .oauth2Login().successHandler(((request, response, authentication) -> {
                    log.error("认证成功");
            OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken)authentication;
                    log.info("{} 在github上的信息是：{}", oAuth2AuthenticationToken.getPrincipal().getName(),
                            oAuth2AuthenticationToken);
                }));
    }
}
```
* /public 是不需要认证就可以访问的
* /admin 是需要admin角色才能访问的
* /user 是需要user角色才能访问的
* /index 是需要认证的

`@EnableGlobalMethodSecurity` 注解允许在方法级别使用@PreAuthorize("hasAnyAuthority('ROLE_USER, SCOPE_user')")

## 测试接口


```java
@RestController
public class ResourceController {

    /**
     * 通过token，可以访问github上的其他资源
     * curl -X GET \
     *   https://api.github.com/user \
     *   -H 'Authorization: Bearer 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' \
     * @param authorizedClient
     * @return
     */
    @GetMapping(value = {"index", "/"})
    public String index(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
        return "index token = " + authorizedClient.getAccessToken().getTokenValue();
    }

    /**
     * 403没有访问权限
     * @return
     */
    @GetMapping(value = "admin")
    public String admin() {
        return "admin";
    }

	@PreAuthorize("hasAnyAuthority('ROLE_USER, SCOPE_user')")
    @GetMapping(value = "user")
    public String user() {
        return "user";
    }

    /**
     * 不需要认证就能访问
     * @return
     */
    @GetMapping(value = "public")
    public String publicFun() {
        return "public";
    }
}
```


# 源码分析
* `OAuth2AuthorizationRequestRedirectFilter.java`

```java
    private void sendRedirectForAuthorization(HttpServletRequest request, HttpServletResponse response, OAuth2AuthorizationRequest authorizationRequest) throws IOException {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(authorizationRequest.getGrantType())) {
            this.authorizationRequestRepository.saveAuthorizationRequest(authorizationRequest, request, response);
        }

        this.authorizationRedirectStrategy.sendRedirect(request, response, authorizationRequest.getAuthorizationRequestUri());
    }
```
拦截器组装数据后跳转以下URL
```
https://github.com/login/oauth/authorize?response_type=code&client_id=&redirect_uri=http://localhost:8080/login/oauth2/code/github
```

* `OAuth2LoginAuthenticationFilter.java`

```java
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        MultiValueMap<String, String> params = OAuth2AuthorizationResponseUtils.toMultiMap(request.getParameterMap());
        if (!OAuth2AuthorizationResponseUtils.isAuthorizationResponse(params)) {
            OAuth2Error oauth2Error = new OAuth2Error("invalid_request");
            throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
        } else {
            OAuth2AuthorizationRequest authorizationRequest = this.authorizationRequestRepository.removeAuthorizationRequest(request, response);
            if (authorizationRequest == null) {
                OAuth2Error oauth2Error = new OAuth2Error("authorization_request_not_found");
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            } else {
                String registrationId = (String)authorizationRequest.getAttribute("registration_id");
                ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId(registrationId);
                if (clientRegistration == null) {
                    OAuth2Error oauth2Error = new OAuth2Error("client_registration_not_found", "Client Registration not found with Id: " + registrationId, (String)null);
                    throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
                } else {
                    String redirectUri = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).replaceQuery((String)null).build().toUriString();
                    OAuth2AuthorizationResponse authorizationResponse = OAuth2AuthorizationResponseUtils.convert(params, redirectUri);
                    Object authenticationDetails = this.authenticationDetailsSource.buildDetails(request);
                    OAuth2LoginAuthenticationToken authenticationRequest = new OAuth2LoginAuthenticationToken(clientRegistration, new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
                    authenticationRequest.setDetails(authenticationDetails);
                    // 委托Provider认证，认证成功后，返回OAuth2LoginAuthenticationToken
                    OAuth2LoginAuthenticationToken authenticationResult = (OAuth2LoginAuthenticationToken)this.getAuthenticationManager().authenticate(authenticationRequest);
                    OAuth2AuthenticationToken oauth2Authentication = new OAuth2AuthenticationToken(authenticationResult.getPrincipal(), authenticationResult.getAuthorities(), authenticationResult.getClientRegistration().getRegistrationId());
                    oauth2Authentication.setDetails(authenticationDetails);
                    OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(authenticationResult.getClientRegistration(), oauth2Authentication.getName(), authenticationResult.getAccessToken(), authenticationResult.getRefreshToken());
                    this.authorizedClientRepository.saveAuthorizedClient(authorizedClient, oauth2Authentication, request, response);
                    return oauth2Authentication;
                }
            }
        }
    }
```

`OAuth2LoginAuthenticationFilter` 的作用很简单，就是响应授权服务器的回调地址（/login/oauth2/code/github），核心之处在于`OAuth2LoginAuthenticationProvider` 对 `OAuth2LoginAuthenticationToken` 的认证。

`OAuth2LoginAuthenticationProvider.java`

```java
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2LoginAuthenticationToken loginAuthenticationToken = (OAuth2LoginAuthenticationToken)authentication;
        if (loginAuthenticationToken.getAuthorizationExchange().getAuthorizationRequest().getScopes().contains("openid")) {
            return null;
        } else {
            OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthenticationToken;
            try {
                authorizationCodeAuthenticationToken = (OAuth2AuthorizationCodeAuthenticationToken)this.authorizationCodeAuthenticationProvider.authenticate(new OAuth2AuthorizationCodeAuthenticationToken(loginAuthenticationToken.getClientRegistration(), loginAuthenticationToken.getAuthorizationExchange()));
            } catch (OAuth2AuthorizationException var9) {
                OAuth2Error oauth2Error = var9.getError();
                throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
            }

            OAuth2AccessToken accessToken = authorizationCodeAuthenticationToken.getAccessToken();
            Map<String, Object> additionalParameters = authorizationCodeAuthenticationToken.getAdditionalParameters();
            OAuth2User oauth2User = this.userService.loadUser(new OAuth2UserRequest(loginAuthenticationToken.getClientRegistration(), accessToken, additionalParameters));
            Collection<? extends GrantedAuthority> mappedAuthorities = this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());
            OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(loginAuthenticationToken.getClientRegistration(), loginAuthenticationToken.getAuthorizationExchange(), oauth2User, mappedAuthorities, accessToken, authorizationCodeAuthenticationToken.getRefreshToken());
            authenticationResult.setDetails(loginAuthenticationToken.getDetails());
            return authenticationResult;
        }
    }
```

`OAuth2LoginAuthenticationToken.java`

```java
    public OAuth2LoginAuthenticationToken(ClientRegistration clientRegistration, OAuth2AuthorizationExchange authorizationExchange, OAuth2User principal, Collection<? extends GrantedAuthority> authorities, OAuth2AccessToken accessToken, @Nullable OAuth2RefreshToken refreshToken) {
        super(authorities);
        Assert.notNull(clientRegistration, "clientRegistration cannot be null");
        Assert.notNull(authorizationExchange, "authorizationExchange cannot be null");
        Assert.notNull(principal, "principal cannot be null");
        Assert.notNull(accessToken, "accessToken cannot be null");
        this.clientRegistration = clientRegistration;
        this.authorizationExchange = authorizationExchange;
        this.principal = principal;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.setAuthenticated(true);
    }
```
`OAuth2LoginAuthenticationToken` 有principal accessToken refreshToken等信息

参考阅读：

[https://www.zyc.red/Spring/Security/OAuth2/OAuth2-Client/](https://www.zyc.red/Spring/Security/OAuth2/OAuth2-Client/https://www.zyc.red/Spring/Security/OAuth2/OAuth2-Client/)