package com.springboot.template.user.dto;

import com.springboot.template.auth.entity.ProviderType;
import com.springboot.template.auth.entity.RoleType;
import com.springboot.template.user.entity.User;
import lombok.*;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PROTECTED)
@Builder
public class UserDto {
    @NotNull
    private Long userNo;
    @NotNull
    @Size(max = 15)
    private String userId;
    @Size(max = 20)
    private String userPassword;
    @NotNull
    @Size(max = 30)
    private String userName;
    @NotNull
    @Size(max = 255)
    private String userEmail;
    @NotNull
    @Size(max = 50)
    private String userPhone;
    @NotNull
    @Size(max = 8)
    private String userBirthDate;
    @NotNull
    @Size(max = 1)
    private String userGender;
    @NotNull
    private boolean userTerms;
    @NotNull
    private ProviderType providerType;
    @NotNull
    private RoleType roleType;
    @NotNull
    private LocalDateTime createdAt;
    @NotNull
    private boolean userActive;

    // entity -> dto
    @Builder
    public UserDto (User user) {
        this.userNo = user.getUserNo();
        this.userId = user.getUserId();
        this.userPassword = user.getUserPassword();
        this.userName = user.getUserName();
        this.userEmail = user.getUserEmail();
        this.userPhone = user.getUserPhone();
        this.userBirthDate = user.getUserBirthDate();
        this.userGender = user.getUserGender();
        this.userTerms = user.isUserTerms();
        this.providerType = user.getProviderType();
        this.roleType = user.getRoleType();
        this.createdAt = user.getCreatedAt();
        this.userActive = user.isUserActive();
    }

    // dto -> entity
    public User toEntity () {
        return User.builder()
                .userId(userId)
                .userName(userName)
                .userEmail(userEmail)
                .userPhone(userPhone)
                .userBirthDate(userBirthDate)
                .userGender(userGender)
                .userTerms(userTerms)
                .providerType(providerType)
                .roleType(roleType)
                .createdAt(createdAt)
                .userActive(userActive)
                .build();
    }
}
