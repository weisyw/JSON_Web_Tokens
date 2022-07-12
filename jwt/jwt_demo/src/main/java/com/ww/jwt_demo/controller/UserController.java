package com.ww.jwt_demo.controller;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ww.jwt_demo.pojo.User;
import com.ww.jwt_demo.service.IUserService;
import com.ww.jwt_demo.utils.JWTUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 9:35
 * @Description: This is description of class
 */

@RestController
@Slf4j
public class UserController {

    @Autowired
    private IUserService userService;

    @GetMapping("/user/login")
    public Map<String, Object> login(User user){
        log.info("用户名：{} , 密码：{}",user.getName(),user.getPassword());
        Map<String, Object> map = new HashMap<>();
        try{
            User login = userService.login(user);
            // 生成jwt令牌
            Map<String, String> payload = new HashMap<>();
            payload.put("id", login.getId());
            payload.put("name", login.getName());
            String token = JWTUtils.getToken(payload);
            map.put("state", true);
            map.put("msg", "认证成功");
            map.put("token", token);
        }catch (Exception e){
            map.put("state", false);
            map.put("msg", e.getMessage());
        }
        return map;
    }

    @PostMapping("/user/test")
    public Map<String, Object> test(String token){
        log.info("当前token为：{}", token);
        Map<String, Object> map = new HashMap<>();
        // 处理自己的业务逻辑
        map.put("state", true);
        map.put("msg", "认证成功");
        return map;
    }
}
