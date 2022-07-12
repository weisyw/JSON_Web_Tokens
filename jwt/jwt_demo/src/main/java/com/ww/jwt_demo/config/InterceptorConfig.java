package com.ww.jwt_demo.config;

import com.ww.jwt_demo.interceptor.JWTInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 11:27
 * @Description: This is description of class
 */
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new JWTInterceptor())
                .addPathPatterns("/user/test") // 用户接口放行，其他接口token验证
                .excludePathPatterns("/user/login");
    }
}
