package com.ww.jwt_demo.service;

import com.ww.jwt_demo.pojo.User;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 9:30
 * @Description: This is description of class
 */
public interface IUserService {
    User login(User user);
}
