package com.avenger.director.adapter;

import com.avenger.director.app.LoginService;
import javax.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Description:
 *
 * Date: 2021/5/16
 *
 * @author JiaDu
 * @version 1.0.0
 */
@Slf4j
@RestController
@RequestMapping("api/sign")
public class LoginAdapter {

    @Resource
    private LoginService loginService;

    @GetMapping("in")
    public Object signIn(@RequestParam("loginName") String loginName, @RequestParam("loginPwd") String loginPwd) {
        return loginService.signIn(loginName, loginPwd);
    }


    @GetMapping("out")
    public Object signOut() {
        return loginService.signOut();
    }
}
