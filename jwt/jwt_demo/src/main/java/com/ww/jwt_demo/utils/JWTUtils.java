package com.ww.jwt_demo.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 9:01
 * @Description: JWT工具类
 */
public class JWTUtils {

    private static final String SING = "1qaz2wsx";

    /**
     * 生成token
     * @param map
     * @return
     */
    public static String getToken(Map<String, String> map){

        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.DATE, 3);

        JWTCreator.Builder builder = JWT.create();

        map.forEach((key, value) -> {
            builder.withClaim(key, value);
        });

        String token = builder.withExpiresAt(instance.getTime())
                .sign(Algorithm.HMAC256(SING));

        return token;
    }

    /**
     * 验证token合法性 获取token信息
     * @param token
     * @return
     */
    public static DecodedJWT verify(String token) {
        //如果有任何验证异常，此处都会抛出异常
        return JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
    }

    /**
     * 获取token信息
     * @param token
     * @return
     */
//    public static DecodedJWT getTokenInfo(String token){
//        DecodedJWT verify = JWT.require(Algorithm.HMAC256(SING)).build().verify(token);
//        return verify;
//    }

}
