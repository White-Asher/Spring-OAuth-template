package com.springboot.template.user.controller;

import com.springboot.template.common.ApiResponse;
import com.springboot.template.user.entity.User;
import com.springboot.template.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping
    public ApiResponse<?> getUser() {
        org.springframework.security.core.userdetails.User principal = (org.springframework.security.core.userdetails.User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        log.info("getUser principal : {}", principal);
        User user = userService.getUser(principal.getUsername());
        log.info("getUser user : {}", user);
        return ApiResponse.success("user", user);
    }
}