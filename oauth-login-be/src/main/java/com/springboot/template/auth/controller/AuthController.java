package com.springboot.template.auth.controller;

import com.springboot.template.auth.dto.AuthReqModel;
import com.springboot.template.auth.service.CustomUserDetailsService;
import com.springboot.template.common.error.errorcode.UserErrorCode;
import com.springboot.template.common.error.exception.RestApiException;
import com.springboot.template.common.error.response.ErrorResponse;
import com.springboot.template.common.response.RestApiResponse;
import com.springboot.template.config.properties.OpenApiConfig;
import com.springboot.template.config.properties.TokenProperties;
import com.springboot.template.auth.entity.UserPrincipal;
import com.springboot.template.auth.token.AuthToken;
import com.springboot.template.auth.token.AuthTokenProvider;
import com.springboot.template.user.dto.UserResponseDto;
import com.springboot.template.utils.CookieUtil;
import com.springboot.template.utils.RedisUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "auth", description = "로그인, 로그아웃 API")

public class AuthController {

    private final TokenProperties tokenProperties;
    private final AuthTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService customUserDetailsService;
    private final RedisUtil redisUtil;

    @PostMapping("/login")
    @Operation(summary = "일반 로그인", description = "일반 로그인 API", tags = {"auth"})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OK : 성공", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = String.class)),
                    @Content(mediaType = "*/*", schema = @Schema(implementation = RestApiResponse.class)) }),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST : 잘못된 요청", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "NOT FOUND : 잘못된 서버 경로 요청", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR : 서버 에러", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "USER_400", description = "로그인 실패 : ID, PW 확인", content = @Content(schema = @Schema(implementation = ErrorResponse.class)))
    })
    public RestApiResponse<String> login(HttpServletRequest request, HttpServletResponse response,
            @Parameter(description = "로그인 아이디, 비밀번호") @RequestBody AuthReqModel authReqModel
    ) {
        log.info("/api/auth/login | Post Method | 일반로그인 호출됨");
        log.info("authReqModel : {}", authReqModel);
        Authentication authentication = null;

        // ID, PW 검증
        try {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authReqModel.getId(), 
                            authReqModel.getPassword()
                    )
            );
        } catch (BadCredentialsException | InternalAuthenticationServiceException e) {
            log.info("/api/auth/login | Post Method | 로그인 검증 실패");
            throw new RestApiException(UserErrorCode.USER_400);
        }
        
        log.info("authentication : {} ", authentication);

        // 로그인 정보를 SecurityContextHolder에 적재함.
        String userId = authReqModel.getId();
        SecurityContextHolder.getContext().setAuthentication(authentication);

        Date now = new Date();
        // Access Token 생성 (id, role, expireTime)
        AuthToken accessToken = tokenProvider.createAuthToken(
                userId,
                ((UserPrincipal) authentication.getPrincipal()).getRoleType().getCode(),
                new Date(now.getTime() + tokenProperties.getAuth().getAccessTokenExpiry())
        );

        log.info("Create Access Token : {} ", accessToken);

        // Refresh Token 생성 (id, role, expireTime)
        long refreshTokenExpiry = tokenProperties.getAuth().getRefreshTokenExpiry();
        AuthToken refreshToken = tokenProvider.createAuthToken(
                userId,
                ((UserPrincipal) authentication.getPrincipal()).getRoleType().getCode(),
                new Date(now.getTime() + refreshTokenExpiry)
        );

        log.info("Create Refresh Token : {} ", refreshToken);

        // Redis 에 키값으로 userId가 있으면(refreshtoken이 있다면...) redis 에서 삭제 수행.
        if (redisUtil.getData(userId) != null) {
            log.info("refresh token redis exists and Remove refresh token");
            redisUtil.delData(userId);
        }

        // redis 에 refresh 토큰 새로 넣기
        redisUtil.setDataExpire(userId, refreshToken.getToken(), refreshTokenExpiry);
        
        // 쿠키 만료시간 설정
        int cookieMaxAge = (int) refreshTokenExpiry;
        CookieUtil.deleteCookie(request, response, tokenProperties.getAuth().getRefreshTokenName());
        CookieUtil.addCookie(response, tokenProperties.getAuth().getRefreshTokenName(), refreshToken.getToken(), cookieMaxAge);
        
        // Header Authorization 에 AccessToken 적재
        response.setContentType("application/json;charset=UTF-8");
        response.setHeader(tokenProperties.getAuth().getAccessTokenHeaderName(),
                    tokenProperties.getAuth().getAccessTokenHeaderPrefix() + accessToken.getToken());
        return new RestApiResponse<>("로그인 완료");
    }

    @PostMapping("/logout")
    @Operation(summary = "일반 로그아웃", description = "일반 로그아웃 API", tags = {"auth"})
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "OK : 성공", content = {
                    @Content(mediaType = "application/json", schema = @Schema(implementation = String.class)),
                    @Content(mediaType = "*/*", schema = @Schema(implementation = RestApiResponse.class)) }),
            @ApiResponse(responseCode = "400", description = "BAD REQUEST : 잘못된 요청", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "404", description = "NOT FOUND : 잘못된 서버 경로 요청", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "INTERNAL SERVER ERROR : 서버 에러", content = @Content(schema = @Schema(implementation = ErrorResponse.class))),
    })
    @SecurityRequirement(name = OpenApiConfig.securitySchemeName)
    public RestApiResponse<UserResponseDto> logout(HttpServletRequest request, HttpServletResponse response) {
        UserResponseDto userResponseDto = customUserDetailsService.currentLoadUserByUserId();
        return new RestApiResponse<>("로그아웃 완료", userResponseDto);
    }

//    @GetMapping("/refresh")
//    @Operation(summary = "Refresh token 재발급", description = "Refresh token 재발급 API", tags = {"auth"})
//    public ResponseEntity<?> refreshToken (HttpServletRequest request, HttpServletResponse response) {
//        // access token 확인
//        String accessToken = HeaderUtil.getAccessToken(request);
//        AuthToken authToken = tokenProvider.convertAuthToken(accessToken);
////        authToken.validate();
//
////        if (!authToken.validate()) {
////            return ApiResponse.invalidAccessToken();
////        }
//
//        // expired access token 인지 확인
////        Claims claims = authToken.getExpiredTokenClaims();
//        Claims claims = authToken.getTokenClaims();
//
////        if (claims == null) {
////            return ApiResponse.notExpiredTokenYet();
////        }
//
//        String userId = claims.getSubject();
//        RoleType roleType = RoleType.of(claims.get("role", String.class));
//
//        // refresh token
//        String refreshToken = CookieUtil.getCookie(request, REFRESH_TOKEN)
//                .map(Cookie::getValue)
//                .orElse((null));
//        AuthToken authRefreshToken = tokenProvider.convertAuthToken(refreshToken);
//        authRefreshToken.validate();
//
////        if (authRefreshToken.validate()) {
////            return ApiResponse.invalidRefreshToken();
////        }
//
//        // userId refresh token 으로 DB 확인
//        String userRefreshToken = redisUtil.getData((String) userId);
//        // UserRefreshToken userRefreshToken = userRefreshTokenRepository.findByUserIdAndRefreshToken(userId, refreshToken);
//        if (userRefreshToken == null) {
//            throw new JwtException("토큰이 유효하지 않음");
//        }
//
//        Date now = new Date();
//        AuthToken newAccessToken = tokenProvider.createAuthToken(
//                userId,
//                roleType.getCode(),
//                new Date(now.getTime() + appProperties.getAuth().getTokenExpiry())
//        );
//
//        long validTime = authRefreshToken.getTokenClaims().getExpiration().getTime() - now.getTime();
//
//        // refresh 토큰 기간이 3일 이하로 남은 경우, refresh 토큰 갱신
//        if (validTime <= THREE_DAYS_MSEC) {
//            // refresh 토큰 설정
//            long refreshTokenExpiry = appProperties.getAuth().getRefreshTokenExpiry();
//
//            authRefreshToken = tokenProvider.createAuthToken(
//                    userId,
//                    roleType.getCode(),
//                    new Date(now.getTime() + refreshTokenExpiry)
//            );
//
//            // DB에 refresh 토큰 업데이트
//            // userRefreshToken.setRefreshToken(authRefreshToken.getToken());
//            redisUtil.setDataExpire(userId, authRefreshToken.getToken(), refreshTokenExpiry);
//
//            int cookieMaxAge = (int) refreshTokenExpiry / 60;
//            CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
//            CookieUtil.addCookie(response, REFRESH_TOKEN, authRefreshToken.getToken(), cookieMaxAge);
//        }
//
//        return ResponseEntity.ok().body(newAccessToken.getToken());
//    }
}
