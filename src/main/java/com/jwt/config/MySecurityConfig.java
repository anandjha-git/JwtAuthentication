package com.jwt.config;

import com.jwt.services.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private  JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private  JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    /*
        @EnableWebSecurity is a Spring Security annotation that enables web security configuration.
    */

    /*
         CSRF Protection Disabled: csrf().disable() disables Cross-Site Request Forgery protection.
         CSRF protection helps to prevent malicious websites from making requests to your application on behalf of authenticated users.
         Disabling CSRF can make your application vulnerable to certain attacks, so ensure this is necessary for your use case.
    */

    /*
        Disabling CORS means your application will not accept requests from other origins,
        which could limit integration with other web applications or front-end frameworks that are served from different domains.
        Disabling it can limit your application's ability to integrate with other services or applications running on different domains.
    */

    /*
        Request Authorization: Determines which requests require authentication.
    */

    /*
        .antMatchers("/public/**").permitAll(): Allows public access to URLs starting with /public/.
    */

    /*
        .anyRequest().authenticated(): Requires authentication for all other requests.
    */

    /*
        SessionCreationPolicy.STATELESS indicates that the application does not use HTTP sessions to store the user's state.
        In a stateless session policy, the server does not keep track of the client state between requests.
        Each request from the client must contain all the information the server needs to process it.
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf()
                .disable()
                .cors()
                .disable()
                .authorizeRequests()
                .antMatchers("/token").permitAll()
                .anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().authenticationEntryPoint(jwtAuthenticationEntryPoint);

        http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(customUserDetailsService);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
