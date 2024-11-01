package com.security.jwttoken.controller;

import com.security.jwttoken.dto.AuthRequest;
import com.security.jwttoken.dto.CreateUserRequest;
import com.security.jwttoken.model.User;
import com.security.jwttoken.service.AuthService;
import com.security.jwttoken.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
@RequiredArgsConstructor
@RequestMapping("/auth")
public class UserController {

    private final UserService service;
    private final AuthService authService;

    @GetMapping("/welcome")
    public String welcome() {
        return "Hello World. My name is Ömer";
    }

    @PostMapping("/addNewUser")
    public User addUser(@RequestBody CreateUserRequest request) {
        return service.createUser(request);
    }

    @PostMapping("/generateToken")
    public String generateToken(@RequestBody AuthRequest request) {
        return authService.generateToken(request);
    }


    @GetMapping("/user")
    public String getUserString() {
        return "This is USER";
    }

    @GetMapping("/admin")
    public String getAdminString() {
        return "This is ADMIN";
    }

}
