package com.example.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(); //单例模式对象不能new出来，只能通过getInstance方法
    }
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("ajian").password("$2a$10$Kl3o4ubuwdyC8VAMI4CE1.SZSBgEcGm1ap8h6ZGUhywrIi6ZCKec2").roles("admin")
                .and()
                .withUser("laji").password("$2a$10$.7e3IGQqXP1vU69lY1/DWeOVRm/aFa/DYMToTZcwZtpX3eFTbFTSS").roles("user");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()////开启登录配置
            .antMatchers("/admin/**").hasRole("admin")//表示访问 /hello 这个接口，需要具备 admin 这个角色
                .antMatchers("/user/**").hasAnyRole("admin","user")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/doLogin")//登录处理接口
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        Map<String,Object> map=new HashMap<>();
                        map.put("status",200);
                        map.put("msg",authentication.getPrincipal());
                        out.write(new ObjectMapper().writeValueAsString(map)); //把一个对象转成json字符串
                        out.flush();
                        out.close();
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest req, HttpServletResponse resp, AuthenticationException e) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        Map<String,Object> map=new HashMap<>();
                        map.put("status",401);
                        if( e instanceof LockedException){
                            map.put("msg","账户被锁定了");
                        }else if(e instanceof BadCredentialsException){
                            map.put("msg","用户名或密码输入错误，登陆失败");
                        }else if(e instanceof DisabledException){
                            map.put("msg","账户被禁用，登陆失败");
                        }else if(e instanceof AccountExpiredException){
                            map.put("msg","账户过期，登陆失败");
                        }else if(e instanceof CredentialsExpiredException){
                            map.put("msg","密码过期，登陆失败");
                        }
                        out.write(new ObjectMapper().writeValueAsString(map)); //把一个对象转成json字符串
                        out.flush();
                        out.close();
                    }
                })
                .permitAll() //与表单登陆有关的接口统统过
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest req, HttpServletResponse resp, Authentication authentication) throws IOException, ServletException {
                        resp.setContentType("application/json;charset=utf-8");
                        PrintWriter out = resp.getWriter();
                        Map<String,Object> map=new HashMap<>();
                        map.put("status",200);
                        map.put("msg","注销登陆成功");
                        out.write(new ObjectMapper().writeValueAsString(map)); //把一个对象转成json字符串
                        out.flush();
                        out.close();
                    }
                })
                .and()
                .csrf().disable();
    }
}
