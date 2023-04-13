package com.springboot.template.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * 이 코드는 스프링 부트 애플리케이션에서 사용되는 유틸리티 클래스인 HeaderUtil입니다. <br>
 * 이 클래스는 HTTP 요청에서 토큰을 추출하는 기능을 제공합니다. <br>
 * 해당 클래스는 @Component 어노테이션이 지정되어 있어 스프링이 컴포넌트 스캔을 수행할 때 빈으로 등록되어 사용됩니다. <br>
 * 또한 @Slf4j 어노테이션으로 인해 log 객체가 생성되어 로그 출력에 사용됩니다. <br>
 * getAccessToken 메서드는 HttpServletRequest 객체와 두 개의 문자열 파라미터(headerAuth와 tokenPrefix)를 입력 받습니다.
 * 이 메서드는 HttpServletRequest에서 headerAuth 이름으로 지정된 HTTP 헤더 값을 가져와서 출력하고, 해당 값이 null이면 null을 반환합니다. <br>
 * headerAuth 문자열이 tokenPrefix로 시작하면, tokenPrefix의 길이 이후의 문자열을 반환합니다.  <br>
 * 그렇지 않으면 null을 반환합니다. 이 메서드는 대개 JWT 토큰을 추출하기 위해 사용됩니다.
 */

@Slf4j
@Component
public class HeaderUtil {

    public static String getAccessToken(HttpServletRequest request, String headerAuth, String tokenPrefix) {
        String headerValue = request.getHeader(headerAuth);
        log.info("Access Token (HEADER) = {}", headerValue);
        if (headerValue == null) {
            return null;
        }
        if (headerValue.startsWith(tokenPrefix)) {
            return headerValue.substring(tokenPrefix.length());
        }
        return null;
    }
}