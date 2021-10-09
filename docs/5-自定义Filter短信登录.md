# 组件Filter、Provider、AuthenticationToken
`SmsCodeAuthenticationFilter.java`

```java
	public class SmsCodeAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
	
	    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/sms/login",
	            "POST");
	
	    public SmsCodeAuthenticationFilter(AuthenticationManager authenticationManager) {
	        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
	        setAuthenticationManager(authenticationManager);
	    }
	
	    @Override
	    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
	        String mobile = request.getParameter("mobile");
	        String code = request.getParameter("code");
	
	        SmsCodeAuthenticationToken authRequest = new SmsCodeAuthenticationToken(mobile, code);
	        setDetails(request, authRequest);
	        return this.getAuthenticationManager().authenticate(authRequest);
	    }
	
	    protected void setDetails(HttpServletRequest request, SmsCodeAuthenticationToken authRequest) {
	        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	    }
}
```

`SmsCodeAuthenticationToken.java`

```java
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

```

`SmsCodeAuthenticationProvider.java`

```java
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
            throw new BadCredentialsException("验证码不正确！");
        }
    }

}
```

# 添加到配置
* 添加Provider

```java
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(new SmsCodeAuthenticationProvider(username -> new User("jkxyx205", "11", AuthorityUtils.commaSeparatedStringToAuthorityList("USER"))));
    }
```

* 添加Filter

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
	    http.addFilterBefore(new SmsCodeAuthenticationFilter(authenticationManager()), UsernamePasswordAuthenticationFilter.class);
    }
```

# 测试页面
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
>
<head>
    <meta charset="UTF-8">
    <title>自定义登录</title>
    <link href="https://cdn.bootcdn.net/ajax/libs/twitter-bootstrap/5.0.2/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div style="margin: 40px auto; width: 320px;">
        <th:block th:if="${session.SPRING_SECURITY_LAST_EXCEPTION != null}">
            <div th:text="${session.SPRING_SECURITY_LAST_EXCEPTION.message}"></div>
        </th:block>
        <form action="/sms/login" method="post">
            <div class="mb-3 row">
                <label for="mobile" class="visually-hidden">用户名</label>
                <input type="text" class="form-control" id="mobile" name="mobile" value="18898987724">
            </div>
            <div class="mb-3 row">
                <label for="code" class="visually-hidden">手机验证码</label>
                <input type="text" class="form-control" id="code" name="code" value="888888">
            </div>
            <div class="mb-3 row">
                <button type="submit" class="btn btn-primary mb-3">登录</button>
            </div>
        </form>
    </div>
</body>
</html>
```