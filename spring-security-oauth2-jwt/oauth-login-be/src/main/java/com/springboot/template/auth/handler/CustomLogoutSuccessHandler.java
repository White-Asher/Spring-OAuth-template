package com.springboot.template.auth.handler;

import com.springboot.template.auth.service.CustomOAuth2UserService;
import com.springboot.template.auth.token.AuthToken;
import com.springboot.template.auth.token.AuthTokenProvider;
import com.springboot.template.common.error.errorcode.UserErrorCode;
import com.springboot.template.common.error.exception.RestApiException;
import com.springboot.template.common.error.response.ErrorResponse;
import com.springboot.template.common.response.RestApiResponse;
import com.springboot.template.config.properties.TokenProperties;
import com.springboot.template.utils.CookieUtil;
import com.springboot.template.utils.HeaderUtil;
import com.springboot.template.utils.RedisUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.REFRESH_TOKEN;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {
    private final TokenProperties tokenProperties;
    private final RedisUtil redisUtil;
    private final AuthTokenProvider tokenProvider;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.info("로그아웃 시 onLogoutSuccess 로직 수행");
        try {
            // 헤더에서 accesstoken 가져오기
            String accessToken = HeaderUtil.getAccessToken(request,
                    tokenProperties.getAuth().getAccessTokenHeaderName(),
                    tokenProperties.getAuth().getAccessTokenHeaderPrefix());
            log.info("Logout access_token = {}", accessToken);
            if (accessToken == null) {
                throw new RestApiException(UserErrorCode.USER_403);
            }
            // Redis에 엑세스 토큰 블랙리스트 등록
            redisUtil.setDataExpire(accessToken, "true", tokenProperties.getAuth().getAccessTokenExpiry());
            log.info("엑세스 토큰 블랙리스트 등록");

            // context.holder accesstoken 정보 삭제.

            //Cookie에서 RefreshToken을 가져와 Redis에서 RefreshToken 삭제
            String refreshToken  = null;
            try {
                refreshToken = CookieUtil.getRefreshTokenCookie(request, tokenProperties.getAuth().getRefreshTokenName());
            } catch (NullPointerException e) {
                log.info("리프래쉬 토큰이 없음");
            }
            log.info("리프래쉬 토큰 가져오기 : {}", refreshToken);
            AuthToken authRefreshToken = tokenProvider.convertAuthToken(refreshToken);
            // 리프래쉬 토큰이 있으면 redis 에서 삭제하고 쿠키에서 삭제하기
            if(refreshToken != null) {
                String userId = tokenProvider.getClaims(authRefreshToken).getSubject();
                log.info("Log out id = {}", userId);
                redisUtil.delData(userId);
                // 쿠키에서 삭제하기
                CookieUtil.deleteCookie(request, response, REFRESH_TOKEN);
            }

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            final ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            mapper.writeValue(response.getOutputStream(), new RestApiResponse<>("로그아웃 완료"));
            response.setStatus(HttpServletResponse.SC_OK);

//        response.sendRedirect("/");
        } catch (Exception e) {
            log.info("JwtExceptionFilter 에서 에러 받기");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            e.printStackTrace();
            ErrorResponse result = new ErrorResponse("Unauthorized", e.getMessage());
            log.info("Logout ErrorResponse : {}", result);
            final ObjectMapper mapper = new ObjectMapper();
            mapper.registerModule(new JavaTimeModule());
            mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            mapper.writeValue(response.getOutputStream(), result);
            response.setStatus(HttpServletResponse.SC_OK);
        }
    }
}

