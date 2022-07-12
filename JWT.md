## 1、什么是JWT
 JSON Web Token (JWT)是⼀个开放标准(RFC 7519)，它定义了⼀种紧凑的、⾃包含的⽅式，⽤于作为JSON对象在各⽅之间安全地传输信息。该信息可以被验证和信任，因为它是数字签名的。jwt可以使用秘密（使用HMAC算法）或使用RSA或ECDSA的公钥/私钥对进行签名。
## 2、JWT能做什么
### 2.1 授权
这是使⽤JWT的最常⻅场景。⼀旦⽤⼾登录，后续每个请求都将包含 JWT，允许⽤⼾访问该令牌允许的路由、服务和资源。单点登录是现在⼴泛使⽤的JWT的⼀个特性，因为它的开销很⼩，并且可以轻松地跨域使⽤。  
### 2.2 信息交换
JSON Web Token是在各方之间安全地传输信息的好方法。因为可以对JWT进行签名（例如，使用公钥/私钥对），所以您可以确保发件人是他们所说的人。此外，由于签名是使用标头和有效负载计算的，因此您还可以验证内容是否遭到篡改。

## 3、为什么是JWT
### 3.1 基于传统的Session认证
#### 3.1.1 认证方式
http协议本身是一种无状态的协议，而这就意味着如果用户向我们的应用提供了用户名和密码来进行用户认证，那么下一次请求时，用户还要再一次进行用户认证才行，因为根据http协议，我们并不能知道是哪个用户发出的请求，所以为了让我们的应用能识别是哪个用户发出的请求，我们只能在服务器存储一份用户登录的信息，这份登录信息会在响应时传递给浏览器，告诉其保存为cookie,以便下次请求时发送给我们的应用，这样我们的应用就能识别请求来自哪个用户了,这就是传统的基于session认证。
#### 3.1.2 认证流程
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657593899527-a2462179-d7ab-4c25-9d31-dd0e6ce4d675.png#clientId=u323cc76b-ecd7-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=195&id=u76e7a4de&originHeight=195&originWidth=608&originalType=binary&ratio=1&rotation=0&showTitle=false&size=9752&status=done&style=none&taskId=u31696794-e7c8-4dc0-a34b-f62bd48def5&title=&width=608)
#### 3.1.3 问题

1. 每个用户经过我们的应用认证之后，我们的应用都要在服务端做一次记录，以方便用户下次请求的鉴别，通常而言session都是保存在内存中，而随着认证用户的增多，服务端的开销会明显增大；
1. 用户认证之后，服务端做认证记录，如果认证的记录被保存在内存中的话，这意味着用户下次请求还必须要请求在这台服务器上,这样才能拿到授权的资源，这样在分布式的应用上，相应的限制了负载均衡器的能力。这也意味着限制了应用的扩展能力；
1. 因为是基于cookie来进行用户识别的, cookie如果被截获，用户就会很容易受到跨站请求伪造的攻击；
1. 在前后端分离系统中就更加痛苦，也就是说前后端分离在应用解耦后增加了部署的复杂性。通常用户一次请求就要转发多次。如果用session 每次携带sessionid 到服务	器，服务器还要查询用户信息。同时如果用户很多。这些信息存储在服务器内存中，给服务器增加负担。还有就是CSRF（跨站伪造请求攻击）攻击，session是基于cookie进行用户识别的, cookie如果被截获，用户就会很容易受到跨站请求伪造的攻击。还有就是sessionid就是一个特征值，表达的信息不够丰富。不容易扩展。而且如果你后端应用是多节点部署。那么就需要实现session共享机制。	不方便集群应用。

### 3.2 基于JWT认证
#### 3.2.1 认证流程

1. 首先，前端通过Web表单将自己的用户名和密码发送到后端的接口。这一过程一般是一个HTTP POST请求。建议的方式是通过SSL加密的传输（https协议），从而避免敏感信息被嗅探。后端核对用户名和密码成功后，将用户的id等其他信息作为JWT Payload（负载），将其与头部分别进行Base64编码拼接后签名，形成一个JWT(Token)。形成的JWT就是一个形同xxx.yyy.zzz的字符串；
1. 后端将JWT字符串作为登录成功的返回结果返回给前端。前端可以将返回的结果保存在localStorage或sessionStorage上，退出登录时前端删除保存的JWT即可；
1. 前端在每次请求时将JWT放入HTTP Header中的Authorization位。(解决XSS和XSRF问题) HEADER；
1. 后端检查是否存在，如存在验证JWT的有效性。例如，检查签名是否正确；检查Token是否过期；检查Token的接收方是否是自己（可选）；
1. 验证通过后后端使用JWT中包含的用户信息进行其他逻辑操作，返回相应结果。

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657594612642-c35d004f-4ecc-448a-acac-adfac0f408ea.png#clientId=u323cc76b-ecd7-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=546&id=u04846f21&originHeight=546&originWidth=852&originalType=binary&ratio=1&rotation=0&showTitle=false&size=34340&status=done&style=none&taskId=u3506e716-40d5-43ba-b76d-a8bd712a2c3&title=&width=852)
#### 3.2.2 JWT的优势

1. 简洁(Compact)：可以通过URL，POST参数或者在HTTP header发送，因为数据量小，传输速度也很快；
1. 自包含(Self-contained)：负载中包含了所有用户所需要的信息，避免了多次查询数据库；
1. 因为Token是以JSON加密的形式保存在客户端的，所以JWT是跨语言的，原则上任何web形式都支持；
1. 不需要在服务端保存会话信息，特别适用于分布式微服务。

## 4、JWT的结构
### 4.1 令牌组成

- 标头(Header)
- 有效载荷(Payload)
- 签名(Signature)

![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657594907862-79a70080-e604-4999-ac53-86853c1e5759.png#clientId=u323cc76b-ecd7-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=155&id=u87387a87originHeight=155&originWidth=444&originalType=binary&ratio=1&rotation=0&showTitle=false&size=6726&status=done&style=none&taskId=uf063c082-0dc4-4fbd-8350-a00c22c0892&title=&width=444)
通常是一个类似于xxx.yyy.zzz的字符串组成

### 4.2 Header
标头通常由两部分组成：令牌的类型（即JWT）和所使用的签名算法，例如HMAC SHA256或RSA。它会使用 Base64 编码组成 JWT 结构的第一部分。
> 注意:Base64是一种编码，也就是说，它是可以被翻译回原来的样子来的。它并不是一种加密过程。

```json
{
  "alg":"HS256",
  "typ":"JWT"
}
```
### 4.3 Payload
令牌的第二部分是有效负载，其中包含声明。声明是有关实体（通常是用户）和其他数据的声明。同样的，它会使用 Base64 编码组成 JWT 结构的第二部分。
```json
{
  "sub": "123",
  "name": "张三",
  "admin": true
}
```
### 4.4 Signature
header和payload都是使用 Base64 进行编码的，即前端可以解开知道里面的信息。Signature 需要使用编码后的 header 和 payload 以及我们提供的一个密钥(盐)，然后使用 header 中指定的签名算法（HS256）进行签名。签名的作用是保证 JWT 没有被篡改过。中间用 . 隔开。
```tex
HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload),secret);
```

**签名目的**
最后一步签名的过程，实际上是对头部以及负载内容进行签名，防止内容被窜改。如果有人对头部以及负载的内容解码之后进行修改，再进行编码，最后加上之前的签名组合形成新的JWT的话，那么服务器端会判断出新的头部和负载形成的签名和JWT附带上的签名是不一样的。如果要对新的头部和负载进行签名，在不知道服务器加密时用的密钥的话，得出来的签名也是不一样的。

**信息安全问题**
在JWT中，不应该在负载里面加入任何敏感的数据。在上面的例子中，我们传输的是用户的普通信息。这个值实际上不是什么敏感内容，一般情况下被知道也是安全的。但是像密码这样的内容就不能被放在JWT中了。如果将用户的密码放在了JWT中，那么怀有恶意的第三方通过Base64解码就能很快地知道你的密码了。因此JWT适合用于向Web应用传递一些非敏感信息。JWT还经常用于设计用户认证和授权系统，甚至实现Web应用的单点登录。

### 4.5 结合
输出是三个由点分隔的Base64-URL字符串，可以在HTML和HTTP环境中轻松传递这些字符串，与基于XML的标准（例如SAML）相比，它更紧凑。

## 5、使用JWT

1. 引入依赖
```xml
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>java-jwt</artifactId>
  <version>3.4.0</version>
</dependency>
```

2. 生成token
```java
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
```

3. 解析token
```java
@Test
void test(){
    // 创建验证对象
    JWTVerifier jwtVerifier = JWT.require(Algorithm.HMAC256("1qaz2wsx")).build();
    DecodedJWT verify = jwtVerifier.verify(token);
    System.out.println(verify.getClaim("userId").asLong());
    System.out.println(verify.getClaim("username").asString());
    System.out.println("过期时间：" + verify.getExpiresAt());
}
```

4. 常见异常
   1. SignatureVerificationException：签名不一致
   1. TokenExpiredException：令牌过期
   1. AlgorithmMismatchException：算法不匹配
   1. InvalidClaimException：payload失效

## 6、封装工具类
```java
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

```

## 7、整合SpringBoot
### 7.1 测试
```java
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
        try {
            DecodedJWT verify = JWTUtils.verify(token);
            map.put("state", true);
            map.put("msg", "请求成功");
            return map;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg", "签名不⼀致");
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            map.put("msg", "token过期");
        } catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            map.put("msg", "算法不匹配");
        } catch (InvalidClaimException e) {
            e.printStackTrace();
            map.put("msg", "失效的payload");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("msg", "token⽆效");
        }
        map.put("state", false);
        return map;
    }
}
```
**测试**
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657595944511-79ff5782-18f3-417a-b00e-0a085cb30682.png#clientId=u323cc76b-ecd7-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=524&id=u6be43c5b&originHeight=524&originWidth=916&originalType=binary&ratio=1&rotation=0&showTitle=false&size=57770&status=done&style=none&taskId=ua506529a-728b-4f09-a93e-01eba3c7076&title=&width=916)
![image.png](https://cdn.nlark.com/yuque/0/2022/png/25843110/1657595973125-41a264be-ba62-4164-ba99-54eaa1e8899a.png#clientId=u323cc76b-ecd7-4&crop=0&crop=0&crop=1&crop=1&from=paste&height=240&id=u0d512342&originHeight=240&originWidth=933&originalType=binary&ratio=1&rotation=0&showTitle=false&size=26865&status=done&style=none&taskId=u2f309f98-96d6-4123-b9c9-09f6f6f78e7&title=&width=933)

### 7.2 配置拦截器

1. 创建JWTInterceptor
```java
package com.ww.jwt_demo.interceptor;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ww.jwt_demo.utils.JWTUtils;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: ww
 * @DateTime: 2022/7/12 10:08
 * @Description: This is description of class
 */

public class JWTInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Map<String, Object> map = new HashMap<>();
        // 获取请求头中的令牌
        String token = request.getHeader("token");
        try {
            DecodedJWT verify = JWTUtils.verify(token);
            // 放行
            return true;
        } catch (SignatureVerificationException e) {
            e.printStackTrace();
            map.put("msg", "签名不⼀致");
        } catch (TokenExpiredException e) {
            e.printStackTrace();
            map.put("msg", "token过期");
        } catch (AlgorithmMismatchException e) {
            e.printStackTrace();
            map.put("msg", "算法不匹配");
        } catch (InvalidClaimException e) {
            e.printStackTrace();
            map.put("msg", "失效的payload");
        } catch (Exception e) {
            e.printStackTrace();
            map.put("msg", "token⽆效");
        }
        // 设置状态
        map.put("state", false);
        // 将map转为json
        String json = new ObjectMapper().writeValueAsString(map);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().println(json);
        return false;
    }
}
```

2. 添加 拦截器
```java
@Configuration
public class InterceptorConfig implements WebMvcConfigurer {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new JWTInterceptor())
                .addPathPatterns("/user/test") // 用户接口放行，其他接口token验证
                .excludePathPatterns("/user/login");
    }
}
```
