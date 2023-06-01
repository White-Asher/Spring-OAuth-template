package com.springboot.template.user.repository;

import org.springframework.data.repository.CrudRepository;
import com.springboot.template.user.entity.UserRefreshToken;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * redis Refresh token repository
 */
@Repository
@Component
public interface UserRefreshTokenRepository extends CrudRepository<UserRefreshToken,String> {

    Optional<UserRefreshToken> findByValue(String value);
}
