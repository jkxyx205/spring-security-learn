# 说明
`spring-security-oauth` 这个项目不赞成使用了。oauth2已经由Spring Security提供服务。Spring Security没有提供对认证服务器的支持，需要 `spring-authorization-server` 去支持。
[https://spring.io/blog/2020/04/15/announcing-the-spring-authorization-server](https://spring.io/blog/2020/04/15/announcing-the-spring-authorization-server)

```
The Spring Security OAuth project is deprecated. The latest OAuth 2.0 support is provided by Spring Security. See the OAuth 2.0 Migration Guide for further details.

Since Spring Security doesn’t provide Authorization Server support, migrating a Spring Security OAuth Authorization Server see https://spring.io/blog/2020/04/15/announcing-the-spring-authorization-server
```
* [https://github.com/spring-projects/spring-security-oauth](https://github.com/spring-projects/spring-security-oauth)
* [https://github.com/spring-projects/spring-security-oauth2-boot](https://github.com/spring-projects/spring-security-oauth2-boot)
* [https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide](https://github.com/spring-projects/spring-security/wiki/OAuth-2.0-Migration-Guide)


# 配置

## 添加依赖 `build.gradle`

```
    implementation "org.springframework.boot:spring-boot-starter-oauth2-resource-server"
    implementation 'org.springframework.boot:spring-boot-starter-web'
```

## 配置文件 `application.yml`

```yml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          public-key-location: classpath:key.public
          jws-algorithm: RS512

```

## 配置类 `ResourceServerConfig.java`

```java
	@EnableWebSecurity
	public class ResourceServerConfig extends WebSecurityConfigurerAdapter {
	
	    @Override
	    protected void configure(HttpSecurity http) throws Exception {
	        http
	            .authorizeRequests(a -> a
	                    .antMatchers("/public", "/error", "/webjars/**").permitAll()
	                    .antMatchers("/admin").hasAnyRole("admin")
	                    .anyRequest().authenticated()
	            )
	            .oauth2ResourceServer()
	            .jwt();
	    }
	
	}
```
* /public 是不需要认证就可以访问的
* /admin 是需要admin角色才能访问的
* /user 是需要user角色才能访问的
* /index 是需要认证的

## 工具类
### 生成私钥和公钥
```
	@UtilityClass
	@Slf4j
	public class SecurityUtils {
	
	    /**
	     * 私钥
	     */
	    private static final RSAPrivateKey PRIVATE_KEY = RsaKeyConverters.pkcs8().convert(SecurityUtils.class.getResourceAsStream("/key.private"));
	
	    /**
	     * 公钥
	     */
	    private static final RSAPublicKey PUBLIC_KEY = RsaKeyConverters.x509().convert(SecurityUtils.class.getResourceAsStream("/key.public"));
	
	
	    /**
	     * rsa算法加解密时的填充方式
	     */
	    private static final String RSA_PADDING = "RSA/ECB/PKCS1Padding";
	
	    /**
	     * 生成私钥和公钥
	     */
	    public static void keys() {
	        try {
	            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
	            keyPairGen.initialize(2048);
	            KeyPair keyPair = keyPairGen.generateKeyPair();
	            PrivateKey privateKey = keyPair.getPrivate();
	            PublicKey publicKey = keyPair.getPublic();
	            log.info("{}{}{}", "\n-----BEGIN PRIVATE KEY-----\n", Base64.getMimeEncoder().encodeToString(privateKey.getEncoded()), "\n-----END PRIVATE KEY-----");
	            log.info("{}{}{}", "\n-----BEGIN PUBLIC KEY-----\n", Base64.getMimeEncoder().encodeToString(publicKey.getEncoded()), "\n-----END PUBLIC KEY-----");
	        } catch (Exception e) {
	            throw new IllegalStateException(e);
	        }
	    }
	
	    /**
	     * 加密
	     *
	     * @param plaintext 明文
	     * @return 密文
	     */
	    private static String encrypt(String plaintext) {
	        try {
	            Cipher cipher = Cipher.getInstance(RSA_PADDING);
	            cipher.init(Cipher.ENCRYPT_MODE, PUBLIC_KEY);
	            String encrypt = Base64.getEncoder().encodeToString(cipher.doFinal(plaintext.getBytes()));
	            log.info("The plaintext {} is encrypted as: {}", plaintext, encrypt);
	            return encrypt;
	        } catch (Exception e) {
	            throw new IllegalStateException(e);
	        }
	    }
	
	    /**
	     * 解密
	     *
	     * @param cipherText 密文
	     * @return 明文
	     */
	    private static String decrypt(String cipherText) {
	        try {
	            Cipher cipher = Cipher.getInstance(RSA_PADDING);
	            cipher.init(Cipher.DECRYPT_MODE, PRIVATE_KEY);
	            String decrypt = new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
	            log.info("The ciphertext {} is decrypted as: {}", cipherText, decrypt);
	            return decrypt;
	        } catch (Exception e) {
	            throw new IllegalStateException(e);
	        }
	    }
	
	    public static void main(String[] args) {
	        keys();
	    }
	}
```
将文件 `key.private` 和 `key.public` 放到`resources`目录下
### 生成token
```java
public final class JwtUtils {

    /**
     * 私钥
     */
    private static final RSAPrivateKey PRIVATE_KEY = RsaKeyConverters.pkcs8().convert(JwtUtils.class.getResourceAsStream("/key.private"));


    private JwtUtils() {}

    /**
     * 生成jwt
     *
     * @return jwt
     */
    public static String jwt(JWTClaimsSet claimsSet) {
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader(new JWSAlgorithm("RS512")), claimsSet);
            // 私钥签名，公钥验签
            jwt.sign(new RSASSASigner(PRIVATE_KEY));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static void main(String[] args) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("RS512 Rick")
                .issuer("https://xhope.top")
                .claim("scope", "user")
                .build();

        String jwtToken = JwtUtils.jwt(claimsSet);
        System.out.println(jwtToken);
    }

}
```

## 测试接口

```java
@RestController
public class ResourceController {

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

利用 postman 进行测试，将token放到header中

```
curl -X GET \
  http://localhost:8080/admin \
  -H 'Authorization: Bearer eyJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJodHRwczpcL1wveGhvcGUudG9wIiwic3ViIjoiUlM1MTIgUmljayIsInNjb3BlIjoibWVzc2FnZS5yZWFkIG1lc3NhZ2Uud3JpdGUifQ.buy_qLLpLodfEwKwRatnHZctZv7pYrgaiX7gjC79tA5ZQiEI_zpO7IvPE_Pw3CSBBZ7Jfz90y1gIq85RK8pAVbIceARsvVK2t8wGq5N6L6jwmi9drkvEMEIdxIijVYfNH7EXakAqx3aN8siScXWX4VTYaSuSd0LFrzQiV2HDmBd0FMGH2OXJmebnD2HI-zXtp02isUTVLReF13DZWV4cG_sr2aix0BjkSl6fhXu7SLZnJTE0yHI47Sc68O6w6J5rqpYUfD4WtM_C9go3iyzldN4oVh67HvzEaJ62ZIx2sKjTITLE_quISxYEnYc62oR1hL87JkGayi7JFl1Sl6o9BA'
```

如果通过参数传递token，需要修改

```java
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        // 允许参数access_token
        resolver.setAllowUriQueryParameter(true);

        http
            .authorizeRequests(a -> a
                    .antMatchers("/public", "/error", "/webjars/**").permitAll()
                    .antMatchers("/admin").hasAnyRole("admin")
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer()
                .bearerTokenResolver(resolver)
            .jwt();
    }
```
利用浏览器进行测试，将token放到参数access_token中

```
curl -X GET \
  'http://localhost:8080/user?access_token=eyJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJodHRwczpcL1wveGhvcGUudG9wIiwic3ViIjoiUlM1MTIgUmljayIsInNjb3BlIjoibWVzc2FnZS5yZWFkIG1lc3NhZ2Uud3JpdGUifQ.buy_qLLpLodfEwKwRatnHZctZv7pYrgaiX7gjC79tA5ZQiEI_zpO7IvPE_Pw3CSBBZ7Jfz90y1gIq85RK8pAVbIceARsvVK2t8wGq5N6L6jwmi9drkvEMEIdxIijVYfNH7EXakAqx3aN8siScXWX4VTYaSuSd0LFrzQiV2HDmBd0FMGH2OXJmebnD2HI-zXtp02isUTVLReF13DZWV4cG_sr2aix0BjkSl6fhXu7SLZnJTE0yHI47Sc68O6w6J5rqpYUfD4WtM_C9go3iyzldN4oVh67HvzEaJ62ZIx2sKjTITLE_quISxYEnYc62oR1hL87JkGayi7JFl1Sl6o9BA'
```

# 源码分析
`BearerTokenAuthenticationFilter.java`

* **获取token：**从header中获取name是 `Authorization` 的值， 判断是否是以 `Bearer` 开头，如果是，那么解析出token值；否则如果允许参数传递token，则尝试从参数access_token中解析token。
* **验证token：**将值包装成 `BearerTokenAuthenticationToken`，交由 `AuthenticationManager`，最终由 `JwtAuthenticationProvider` 进行验证。
* **底层解析token：** 由	`NimbusJwtDecoder` 进行decode；如果是 `SignedJWT` 使用公钥(yml中配置的公钥，项目启动的时候就会读取公钥信息)验签；验证成功后token验证由 `DelegatingOAuth2TokenValidator` 代理去进行其他验证。`JwtTimestampValidator` 验证日期是否过期。

`OAuth2ResourceServerJwtConfiguration.java`
 
参考阅读：

* [https://www.zyc.red/Spring/Security/OAuth2/OAuth2-Resource-Server/](https://www.zyc.red/Spring/Security/OAuth2/OAuth2-Resource-Server/)
* [https://juejin.cn/post/6985893815500406791](https://juejin.cn/post/6985893815500406791)