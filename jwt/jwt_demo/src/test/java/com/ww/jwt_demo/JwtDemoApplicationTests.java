package com.ww.jwt_demo;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.jupiter.api.Test;

import java.util.Calendar;
import java.util.HashMap;


class JwtDemoApplicationTests {

    /**
     * 令牌获取
     */
    @Test
    void contextLoads() {
        HashMap<String, Object> map = new HashMap<>();
        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.SECOND, 60);
        String token = JWT.create()
                .withHeader(map) // header
                .withClaim("userId", 1) // payload
                .withClaim("username", "张三")
                .withExpiresAt(instance.getTime()) // 指定令牌的过期时间
                .sign(Algorithm.HMAC256("1qaz2wsx"));// 签名
        System.out.println(token);
    }

    @Test
    void test(){
        // 创建验证对象
        JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("1qaz2wsx")).build();
        DecodedJWT verify = jwtVerifier.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NTc1NDgxMTIsInVzZXJJZCI6MSwidXNlcm5hbWUiOiLlvKDkuIkifQ.ERJhNdXkTpEjXPq7wofpz45t-HLb4V02B884hXBGNtY");
        System.out.println(verify.getClaim("userId").asLong());
        System.out.println(verify.getClaim("username").asString());
        System.out.println("过期时间：" + verify.getExpiresAt());
    }

}
