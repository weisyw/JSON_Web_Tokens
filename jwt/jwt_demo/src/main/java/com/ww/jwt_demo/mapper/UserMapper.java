package com.ww.jwt_demo.mapper;

import com.ww.jwt_demo.pojo.User;
import org.apache.ibatis.annotations.Mapper;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 9:26
 * @Description: This is description of class
 */

@Mapper
public interface UserMapper {

    User login(User user);
}
