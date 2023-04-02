package com.springboot.template.user.repository;

import com.springboot.template.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query(" SELECT u FROM User as u WHERE u.userId=:userId AND u.userActive=true")
    Optional<User> findByUserId(String userId);

    @Query(" SELECT u FROM User as u WHERE u.userId=:userId AND u.userActive=true")
    User findEntityByUserId(String userId);

    @Query(" SELECT u FROM User as u WHERE u.userEmail=:userEmail AND u.userActive=true")
    Optional<User> findByUserEmail(String userEmail);

}
