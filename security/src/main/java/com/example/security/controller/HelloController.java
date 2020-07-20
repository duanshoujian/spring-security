package com.example.security.controller;

import com.example.security.serivce.MethodService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @Autowired
    MethodService methodService;

    @GetMapping("/hello")
    public String helloController(){
        return "hello security";
    }

    @GetMapping("/admin/a")
    public String adminController(){
        return "hello admin";
    }

    @GetMapping("/user/u")
    public String userController(){
        return "hello user";
    }

    @GetMapping("/admin")
    public String admin(){
       return methodService.admin();
    }


    @GetMapping("/user")
    public String user(){
        return methodService.user();
    }

    @GetMapping("/hello1")
    public String hello(){
        return methodService.hello();
    }
}
