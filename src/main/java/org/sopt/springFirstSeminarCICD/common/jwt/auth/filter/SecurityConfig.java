package org.sopt.springFirstSeminar.common.jwt.auth.filter;

import lombok.RequiredArgsConstructor;
import org.sopt.springFirstSeminar.common.jwt.auth.CustomAccessDeniedHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity //web Security를 사용할 수 있게
public class SecurityConfig {
    private final org.sopt.springFirstSeminar.common.jwt.auth.filter.JwtAuthenticationFilter jwtAuthenticationFilter;
    private final org.sopt.springFirstSeminar.common.jwt.auth.filter.CustomJwtAuthenticationEntryPoint customJwtAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;


    private static final String[] AUTH_WHITE_LIST = {"/api/v1/member"};
    private static final String[] ACTUATOR = {"/actuator/health"};

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .requestCache(RequestCacheConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .exceptionHandling(exception ->
                {
                    exception.authenticationEntryPoint(customJwtAuthenticationEntryPoint);
                    exception.accessDeniedHandler(customAccessDeniedHandler);
                });


        http.authorizeHttpRequests(auth -> {
                    auth.requestMatchers(AUTH_WHITE_LIST).permitAll();
                    auth.requestMatchers(ACTUATOR).permitAll();
                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
