package com.rick.security.token.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.rick.common.util.JsonUtils;
import org.apache.commons.collections4.MapUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;

/**
 * @author Rick
 * @createdAt 2021-09-24 17:33:00
 */
public class JWTUtils {

    /**
     * 创建秘钥
     */
    private static final byte[] SECRET = "6MNSobBRCHGIO0fS6MNSobBRCHGIO0fS".getBytes();

    /**
     * 过期时间500秒
     */
    private static final long EXPIRE_TIME = 1000 * 500;


    public static String createToken(Authentication authentication) {
        return createToken(authentication, null);
    }
    /**
     * 生成Token
     * @param authentication
     * @return
     */
    public static String createToken(Authentication authentication, Map<String, Object> additionalInformation) {
        try {
            /**
             * 1.创建一个32-byte的密匙
             */
            MACSigner macSigner = new MACSigner(SECRET);
            /**
             * 2. 建立payload 载体
             */
            JWTClaimsSet.Builder bulder = new JWTClaimsSet.Builder()
                    .subject(authentication.getPrincipal().toString())
                    .issuer("http://xhope.top")
                    .expirationTime(new Date(System.currentTimeMillis() + EXPIRE_TIME))
                    .claim("authorities",
                            authentication.getAuthorities().stream()
                                    .map(grantedAuthority -> grantedAuthority.getAuthority()).toArray());
            
            if (MapUtils.isNotEmpty(additionalInformation)) {
                bulder.claim("details", additionalInformation);
            }
            
            JWTClaimsSet claimsSet = bulder.build();

            /**
             * 3. 建立签名
             */
            SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
            signedJWT.sign(macSigner);

            /**
             * 4. 生成token
             */
            String token = signedJWT.serialize();
            return token;
        } catch (KeyLengthException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static JsonNode toJsonNode(String accessToken) throws ParseException, JOSEException, IOException {
        JWSObject jwsObject = JWSObject.parse(accessToken);
        JWSVerifier jwsVerifier = new MACVerifier(SECRET);
        if (!jwsObject.verify(jwsVerifier)) {
            throw new RuntimeException("无效的token");
        }
        Payload payload = jwsObject.getPayload();
        return JsonUtils.toJsonNode(payload.toString());
    }

    public static Authentication toAuthentication(String accessToken) throws ParseException, JOSEException, IOException {
        JsonNode jsonNode = toJsonNode(accessToken);

        ArrayNode arrayNode = (ArrayNode) jsonNode.get("authorities");
        Iterator<JsonNode> iterator = arrayNode.iterator();
        List<GrantedAuthority> grantedAuthorities = new ArrayList(arrayNode.size());

        while (iterator.hasNext()) {
            grantedAuthorities.add(new SimpleGrantedAuthority(iterator.next().asText()));
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(jsonNode.get("sub").asText()
                , null, grantedAuthorities);

        JsonNode details = jsonNode.get("details");
        if (details != null) {
            authentication.setDetails(JsonUtils.toObject(details.toString(), Map.class));
        }

        return authentication;
    }

    public static void main(String[] args) throws ParseException, JOSEException, IOException {
        /**
         * {
         *   "iss": "http://xhope.top",
         *   "sub": "rick",
         *   "details": {
         *     "hello": "world"
         *   },
         *   "exp": 1634355598,
         *   "authorities": [
         *     "ADMIN",
         *     "p1",
         *     "p2"
         *   ]
         * }
         */
//        Authentication authentication = new UsernamePasswordAuthenticationToken("rick", null,
//                AuthorityUtils.commaSeparatedStringToAuthorityList("ADMIN,p1,p2"));
//        Map<String, Object> info = new HashMap<>();
//        info.put("hello", "world");
//        System.out.println(JWTUtils.createToken(authentication, info));

        Authentication authentication = JWTUtils.toAuthentication("eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOlwvXC94aG9wZS50b3AiLCJzdWIiOiJyaWNrIiwiZGV0YWlscyI6eyJoZWxsbyI6IndvcmxkIn0sImV4cCI6MTYzNDM1NTU5OCwiYXV0aG9yaXRpZXMiOlsiQURNSU4iLCJwMSIsInAyIl19.jGutb5RI1KT-u936HKoH_Wr1mTJta4YkOuvEuZXp1Zg");
    }

}
