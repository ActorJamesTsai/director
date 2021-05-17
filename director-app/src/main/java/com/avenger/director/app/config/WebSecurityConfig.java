package com.avenger.director.app.config;

import com.avenger.director.app.jwt.JWTConfigurer;
import com.avenger.director.app.jwt.JwtAccessDeniedHandler;
import com.avenger.director.app.jwt.JwtAuthenticationEntryPoint;
import com.avenger.director.app.jwt.TokenProvider;
import javax.annotation.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Resource
    private TokenProvider tokenProvider;
    @Resource
    private CorsFilter corsFilter;
    @Resource
    private JwtAuthenticationEntryPoint authenticationErrorHandler;
    @Resource
    private JwtAccessDeniedHandler jwtAccessDeniedHandler;

    // Configure paths and requests that should be ignored by Spring Security ================================

    @Override
    public void configure(WebSecurity web) {
        web.ignoring()
            .antMatchers(HttpMethod.OPTIONS, "/**")

            // allow anonymous resource requests
            .antMatchers(
                "/",
                "/*.html",
                "/favicon.ico",
                "/**/*.html",
                "/**/*.css",
                "/**/*.js",
                "/h2-console/**"
            );
    }

    // Configure security settings ===========================================================================

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            // 禁用 CSRF
            .csrf().disable()
            .addFilterBefore(corsFilter, UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling()
            .authenticationEntryPoint(authenticationErrorHandler)
            .accessDeniedHandler(jwtAccessDeniedHandler)
            // 防止iframe 造成跨域
            .and()
            .headers()
            .frameOptions()
            .sameOrigin()
            // 不创建会话
            .and()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeRequests()
            // 静态资源等等
            .antMatchers(
                HttpMethod.GET,
                "/*.html",
                "/**/*.html",
                "/**/*.css",
                "/**/*.js",
                "/webSocket/**"
            ).permitAll()
            // swagger 文档
            .antMatchers("/swagger-ui.html").permitAll()
            .antMatchers("/swagger-resources/**").permitAll()
            .antMatchers("/webjars/**").permitAll()
            .antMatchers("/*/api-docs").permitAll()
            // 放行OPTIONS请求
            .antMatchers(HttpMethod.OPTIONS, "/**").permitAll()
            .and()
            .authorizeRequests()
            .antMatchers("/api/login").permitAll()
            .anyRequest().authenticated()
            .and()
            .apply(securityConfigurerAdapter());
    }

    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(tokenProvider);
    }
}
