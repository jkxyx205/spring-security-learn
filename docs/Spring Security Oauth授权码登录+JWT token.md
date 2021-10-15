# 说明
* 授权码模式 `authorization_code` 需要进行登录页面验证，所以授权服务器和资源服务器需要**分开部署**！
* 密码模式 `password` 授权服务器和资源服务器可以部署在一起。

# 授权服务器
* 依赖 `pom.xml`
```xml
<!-- spring security 4.2.15 -->
<dependency>
    <groupId>org.springframework.security.oauth.boot</groupId>
    <artifactId>spring-security-oauth2-autoconfigure</artifactId>
    <version>2.5.5</version>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```
* 资源服务器配置 `AuthorizationServer.java`
```java
@Configuration
@EnableAuthorizationServer
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

    @Autowired
    @Qualifier("tokenServices")
    private AuthorizationServerTokenServices authorizationServerTokenServices;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) {
        security
                .tokenKeyAccess("permitAll()") // oauth/token_key是公开
                .checkTokenAccess("permitAll()") // oauth/check_token公开
                .allowFormAuthenticationForClients(); //密码模式：表单认证（申请令牌）
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()// 使用in-memory存储
                .withClient("c")// client_id
                .secret("123456")//客户端密钥
                .resourceIds("res")//资源列表
                .authorizedGrantTypes("authorization_code", "password", "client_credentials", "implicit", "refresh_token")// 该client允许的授权类型authorization_code,password,refresh_token,implicit,client_credentials
                .scopes("all")// 允许的授权范围
                .autoApprove(false)//false跳转到授权页面
                //加上验证回调地址
                .redirectUris("http://www.baidu.com");
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .userDetailsService(userDetailsService)
                .authenticationManager(authenticationManager)// 认证管理器 => 密码模式需要在认证服务器中设置 中配置AuthenticationManager
                .tokenServices(authorizationServerTokenServices)
                .authorizationCodeServices(authorizationCodeServices)
                .allowedTokenEndpointRequestMethods(HttpMethod.POST, HttpMethod.GET);
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

    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }
```
* Token配置 `TokenConfig.java`
```java
@Configuration
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
```
* 配置登录页面 `WebSecurityConfig`
```java
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
}
```
* 配置文件 `application.yml`
```yml
server:
  port: 8081
```

# 资源服务器
* 依赖 `pom.xml`
```xml
<!-- spring security 4.2.15 -->
<dependency>
    <groupId>org.springframework.security.oauth.boot</groupId>
    <artifactId>spring-security-oauth2-autoconfigure</artifactId>
    <version>2.5.5</version>
</dependency>

<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-web</artifactId>
</dependency>
```
* 资源服务配置 `ResourceServer.java`
```java
@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(securedEnabled = true, jsr250Enabled=true, prePostEnabled = true)
public class ResourceServer extends ResourceServerConfigurerAdapter {

    @Autowired
    private TokenStore tokenStore;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        // 资源id
        resources.resourceId("res")
                .stateless(true)
                .tokenStore(tokenStore)
                .accessDeniedHandler((request, response, e) -> {
                    response.getWriter().write(e.getMessage());
                });
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)http.authorizeRequests()
                .antMatchers("/**").access("#oauth2.hasScope('all')")
                .antMatchers("/admin").hasRole("ADMIN")
                .anyRequest()).authenticated();

    }
}

```
* Token配置 `TokenConfig.java`
```java
@Configuration
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
```
* API接口 `IndexController.java`
```java
@RestController
public class IndexController {

    @GetMapping
    public String index() {
        return "index";
    }

    @GetMapping("admin")
    public String admin(Authentication authentication, @RequestParam("access_token") String accessToken, Jwt jwt) {
        return jwt.getClaims();
    }

    @GetMapping("p1")
    @PreAuthorize("hasRole('p1')")
    public String p1(Authentication authentication, @RequestParam("access_token") String accessToken) {
        Jwt jwt = JwtHelper.decode(accessToken);
        return jwt.getClaims();
    }
}
```
* 配置文件 `application.yml`
```yml
server:
  port: 8082
```
# 测试
* 获取授权码
```
http://localhost:8081/oauth/authorize?response_type=code&client_id=c&redirect_uri=http://www.baidu.com&scope=all
```
跳转到登录页面：输入用户名密码：rick/123456；允许授权，获取地址栏授权码 `code`。

* 根据授权码 `code` 获取token
```
curl -X POST \
  http://localhost:8081/oauth/token \
  -H 'content-type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW' \
  -F code=cP8TeB \
  -F grant_type=authorization_code \
  -F client_id=c \
  -F client_secret=123456 \
  -F redirect_uri=http://www.baidu.com \
  -F scope=all
```
返回 `access_token`
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzIl0sInVzZXJfbmFtZSI6InJpY2siLCJzY29wZSI6WyJhbGwiXSwiaGVsbG8iOiJ3b3JsZCIsImV4cCI6MTYzNDI4NTg2MSwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BRE1JTiIsIlJPTEVfcDEiXSwianRpIjoienFOUFZnQVpCeFdwaE9WM1hWZjNZazNkZklVIiwiY2xpZW50X2lkIjoiYyJ9.C7NQVGDgexoZ0VSpbfH_hw1eVXV7JBmB7EH9YydDQlg",
    "token_type": "bearer",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzIl0sInVzZXJfbmFtZSI6InJpY2siLCJzY29wZSI6WyJhbGwiXSwiYXRpIjoienFOUFZnQVpCeFdwaE9WM1hWZjNZazNkZklVIiwiaGVsbG8iOiJ3b3JsZCIsImV4cCI6MTYzNDU0NTAwMSwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BRE1JTiIsIlJPTEVfcDEiXSwianRpIjoiRXdWOXMtYk9mdktGM1V0SFNUc2h3b285dGk0IiwiY2xpZW50X2lkIjoiYyJ9.AWTDhc8Sl4M4tTRC4AdJ1njyhQF5oAXTDNeIfAt3b1o",
    "expires_in": 59,
    "scope": "all",
    "hello": "world",
    "jti": "zqNPVgAZBxWphOV3XVf3Yk3dfIU"
}
```
* 携带 `access_token` 获取资源
```
curl -X GET \
  'http://localhost:8082/p1?access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsicmVzIl0sInVzZXJfbmFtZSI6InJpY2siLCJzY29wZSI6WyJhbGwiXSwiaGVsbG8iOiJ3b3JsZCIsImV4cCI6MTYzNDI4NjAyMSwiYXV0aG9yaXRpZXMiOlsiUk9MRV9BRE1JTiIsIlJPTEVfcDEiXSwianRpIjoibDVVcHF3UUlBWDBMRFVQYWg1T1Q1RDdrVFgwIiwiY2xpZW50X2lkIjoiYyJ9.pknFynXTl8koIUATnoShKbQSOZnwgmP8g4943lfHK7w'
```