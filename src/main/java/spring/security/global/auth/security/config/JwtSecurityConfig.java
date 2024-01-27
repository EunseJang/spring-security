package spring.security.global.auth.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import spring.security.global.auth.security.filter.JwtAuthenticationFilter;
import spring.security.global.auth.security.filter.JwtExceptionFilter;
import spring.security.global.auth.security.jwt.JwtTokenProvider;

@RequiredArgsConstructor
public class JwtSecurityConfig implements SecurityConfigurer<DefaultSecurityFilterChain, HttpSecurity> {

    private final JwtTokenProvider jwtTokenProvider;

    @Override
    public void init(HttpSecurity builder) throws Exception { }

    @Override
    public void configure(HttpSecurity builder) throws Exception {
        JwtAuthenticationFilter customFilter = new JwtAuthenticationFilter(jwtTokenProvider);
        builder.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
        builder.addFilterBefore(new JwtExceptionFilter(), JwtAuthenticationFilter.class);
    }
}