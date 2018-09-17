package com.imooc.security.app.security;

import com.imooc.security.core.authorize.AuthorizeConfigProvider;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.stereotype.Component;

/**
 * Created by Administrator on 2018/9/14.
 */
@Component
@Order(Integer.MAX_VALUE)
public class DemoAuthorizeConifgProvider implements AuthorizeConfigProvider {

    @Override
    public void config(ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config) {
        /**
         * .antMatchers(HttpMethod.GET,
         "/admin/me",
         "/resource").authenticated()
         */
        config.antMatchers(HttpMethod.GET,"/user/me").authenticated()
                .anyRequest().access("@rbacService.hasPermission(request, authentication)");
    }
}
