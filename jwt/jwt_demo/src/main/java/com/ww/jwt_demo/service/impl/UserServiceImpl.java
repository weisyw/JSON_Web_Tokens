package com.ww.jwt_demo.service.impl;

import com.ww.jwt_demo.mapper.UserMapper;
import com.ww.jwt_demo.pojo.User;
import com.ww.jwt_demo.service.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 9:31
 * @Description: This is description of class
 */

@Service
public class UserServiceImpl implements IUserService {

    @Autowired
    private UserMapper userMapper;
    @Override
    public User login(User user) {
        User user1 = userMapper.login(user);
        if (user1 != null) {
            return user1;
        }
        throw new RuntimeException("登录失败");

    }
}
