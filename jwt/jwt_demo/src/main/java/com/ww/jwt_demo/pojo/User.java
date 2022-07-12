package com.ww.jwt_demo.pojo;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 9:23
 * @Description: This is description of class
 */

@Data
@Accessors(chain = true)
public class User {
    private String id;
    private String name;
    private String password;
}
