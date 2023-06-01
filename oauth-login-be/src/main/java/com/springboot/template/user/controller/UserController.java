package com.springboot.template.user.controller;

import com.springboot.template.auth.service.CustomUserDetailsService;
import com.springboot.template.common.error.errorcode.UserErrorCode;
import com.springboot.template.common.error.exception.RestApiException;
import com.springboot.template.common.error.response.ErrorResponse;
import com.springboot.template.common.response.RestApiResponse;
import com.springboot.template.config.OpenApiConfig;
import com.springboot.template.user.dto.UserModifyDto;
import com.springboot.template.user.dto.UserResponseDto;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.springboot.template.user.dto.UserRequestDto;
import com.springboot.template.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
@Tag(name = "user", description = "회원 관련 컨트롤러")
public class UserController {
    private final UserService userService;
    private final CustomUserDetailsService customUserDetailsService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping
    @Operation(summary = "회원 정보 반환", description = "회원 정보 반환 API", tags = {"user"})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OK", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserResponseDto.class)),
                    @Content(mediaType = "*/*", schema = @Schema(implementation = RestApiResponse.class)) }),
            @ApiResponse(responseCode = "USER_402", description = "DB 회원 정보 없음", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
    })
    @SecurityRequirement(name = OpenApiConfig.securitySchemeName)
    public RestApiResponse<?> getUserInfo() {
        log.info("/api/user | GET method | 회원 정보 반환 요청됨");

        UserResponseDto getUser = customUserDetailsService.currentLoadUserByUserId();
        return new RestApiResponse<>("회원 정보 반환 완료", getUser);
    }

    @PostMapping
    @Operation(summary = "회원 가입", description = "회원 가입 API", tags = {"user"})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OK", content = {
                            @Content(mediaType = "application/json", schema = @Schema(implementation = UserResponseDto.class)),
                            @Content(mediaType = "*/*", schema = @Schema(implementation = RestApiResponse.class)) }),
            @ApiResponse(responseCode = "USER_401", description = "회원 ID중복", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "USER_500", description = "DB 등록 실패", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
    })
    public RestApiResponse<?> registerUser(@Valid @RequestBody UserRequestDto userRequestDto) {
        log.info("/api/user | POST method | 회원 가입 요청됨");
        log.info("userRequestDto : {}", userRequestDto);

        // ID 중복 확인
        UserResponseDto userResponseDto = userService.getUser(userRequestDto.getUserId());
        if (userResponseDto != null) {
            throw new RestApiException(UserErrorCode.USER_401);
        }

        // 비밀번호 암호화
        userRequestDto.setUserPassword(passwordEncoder.encode(userRequestDto.getUserPassword()));
        log.info("회원 가입 :  {}", userRequestDto);
        // 회원 정보 DB 입력
        UserResponseDto result = userService.insertUser(userRequestDto);
        // DB 저장 확인
        if(result == null) {
            throw new RestApiException(UserErrorCode.USER_500);
        }
        return new RestApiResponse<>("회원 가입 완료", result);
    }

    @PatchMapping
    @Operation(summary = "회원 정보 수정", description = "회원 정보 수정 API", tags = {"user"})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OK", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserModifyDto.class)),
                    @Content(mediaType = "*/*", schema = @Schema(implementation = RestApiResponse.class)) }),
            @ApiResponse(responseCode = "USER_501", description = "DB 수정 실패", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    @SecurityRequirement(name = OpenApiConfig.securitySchemeName)
    public RestApiResponse<?> modifyUserInfo(@Valid @RequestBody UserModifyDto userModifyDto) {
        log.info("/api/user | PATCH method | 회원 정보 수정 요청됨");
        log.info("userModifyRequestDto : {}", userModifyDto);

        UserResponseDto getUser = customUserDetailsService.currentLoadUserByUserId();
        userModifyDto.setUserId(getUser.getUserId());
        UserModifyDto result = userService.modifyUser(userModifyDto);
        if(result == null) throw new RestApiException(UserErrorCode.USER_501);

        return new RestApiResponse<>("회원 정보 수정 완료", result);
    }

    @DeleteMapping
    @Operation(summary = "회원 정보 삭제", description = "회원 정보 삭제 API", tags = {"user"})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OK", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = UserModifyDto.class)),
                    @Content(mediaType = "*/*", schema = @Schema(implementation = RestApiResponse.class)) }),
            @ApiResponse(responseCode = "USER_501", description = "DB 회원정보 삭제 실패", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
    })
    @SecurityRequirement(name = OpenApiConfig.securitySchemeName)
    public RestApiResponse<?> modifyUserInfo() {
        log.info("/api/user | PATCH method | 회원 정보 삭제 요청됨");

        UserResponseDto getUser = customUserDetailsService.currentLoadUserByUserId();
        userService.deleteUser(getUser.getUserId());
        return new RestApiResponse<>("회원 정보 삭제 완료");
    }

}
