package com.artjava.boot.controller.login;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {

    @PostMapping("/api/auth/token")
    public String token(){
        return "";
    }
}
