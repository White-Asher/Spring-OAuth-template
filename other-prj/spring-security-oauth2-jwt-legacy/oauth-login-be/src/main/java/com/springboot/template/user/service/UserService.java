package com.springboot.template.user.service;

import com.springboot.template.user.dto.UserDto;
import com.springboot.template.user.entity.User;
import com.springboot.template.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getUser(String userId) {
        return userRepository.findByUserId(userId);
    }

//    public UserDto saveUser(UserDto userDto) {
//
//    }
}