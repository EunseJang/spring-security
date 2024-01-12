package spring.security.global.auth.security.config;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring.security.global.auth.security.exception.MyAccessDeniedHandler;
import spring.security.global.auth.security.exception.MyAuthenticationEntryPoint;
import spring.security.global.auth.security.filter.JwtAuthenticationFilter;
import spring.security.global.auth.security.filter.JwtExceptionFilter;

import java.util.Arrays;

@Slf4j
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final Environment environment;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtExceptionFilter jwtExceptionFilter;
    private final MyAccessDeniedHandler myAccessDeniedHandler;
    private final MyAuthenticationEntryPoint myAuthenticationEntryPoint;

    // TODO 비밀번호 인코딩? -> PasswordEncoder

    // Security 인증 검사 필요 X
    private static final String[] PERMIT_URL = {
            // Swagger
            "/v2/api-docs",
            "/swagger-resources/**",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/swagger-ui/**",
            "/webjars/**",

            // Authentication
            "/auth/**"
    };

    /** Spring Security 설정을 구성하는 메서드 */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .httpBasic().disable() // HTTP 기본 인증 비활성화
                .csrf().disable() // CSRF 공격 방어 기능 비활성화
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.formLogin().disable(); // 기본 로그인 페이지 사용 안함

        http
                .authorizeRequests()
                .requestMatchers(PERMIT_URL)
                .permitAll()// PERMIT_URL로 설정한 URL에 대해 모든 사용자 허용
                .requestMatchers("/admin/**")
                .hasAuthority("ROLE_ADMIN") // "/admin/**"은 ADMIN 권한 필요
                .requestMatchers("/**")
                .hasAuthority("ROLE_USER"); // "/**"은 USER 권한 필요

        http
                .exceptionHandling()
                .authenticationEntryPoint(myAuthenticationEntryPoint) // 커스텀 인증 진입 지정 설정
                .accessDeniedHandler(myAccessDeniedHandler); // 커스텀 접근 거부 핸들러 설정

        http
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class) // JWT 필터 추가
                .addFilterBefore(jwtExceptionFilter, JwtAuthenticationFilter.class); // JWT 예외 처리 필터 추가

        // "dev" 프로파일이 활성화되어 있는 경우 모든 URL을 허용
        if(Arrays.asList(environment.getActiveProfiles()).contains("dev")) {
            http.authorizeHttpRequests().requestMatchers("/**").permitAll();
        }

        return http.build(); // SecurityFilterChain 반환
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        // 특정 URL 패턴에 대한 보안 구성 추가 (로그인 페이지, 예외처리 페이지는 인증, 권함 검사 무시 가능)
        return web -> web.ignoring().requestMatchers("/login/**", "/exception/**");
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        // AuthenticationManager 빈을 생성하는 메서드
        return authenticationConfiguration.getAuthenticationManager();
    }
}
