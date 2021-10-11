package com.rick.security.oauth2.resourceserver.util;


import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.converter.RsaKeyConverters;

import java.security.interfaces.RSAPrivateKey;

/**
 * @author zyc
 */
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
        // eyJhbGciOiJSUzUxMiJ9.eyJpc3MiOiJodHRwczpcL1wveGhvcGUudG9wIiwic3ViIjoiUlM1MTIgUmljayIsInNjb3BlIjoibWVzc2FnZS5yZWFkIG1lc3NhZ2Uud3JpdGUifQ.buy_qLLpLodfEwKwRatnHZctZv7pYrgaiX7gjC79tA5ZQiEI_zpO7IvPE_Pw3CSBBZ7Jfz90y1gIq85RK8pAVbIceARsvVK2t8wGq5N6L6jwmi9drkvEMEIdxIijVYfNH7EXakAqx3aN8siScXWX4VTYaSuSd0LFrzQiV2HDmBd0FMGH2OXJmebnD2HI-zXtp02isUTVLReF13DZWV4cG_sr2aix0BjkSl6fhXu7SLZnJTE0yHI47Sc68O6w6J5rqpYUfD4WtM_C9go3iyzldN4oVh67HvzEaJ62ZIx2sKjTITLE_quISxYEnYc62oR1hL87JkGayi7JFl1Sl6o9BA
    }

}
