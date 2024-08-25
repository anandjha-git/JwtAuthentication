package com.jwt.controller;

import com.jwt.model.JwtRequest;
import com.jwt.model.JwtResponse;
import com.jwt.services.CustomUserDetailsService;
import com.jwt.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/token")
    public ResponseEntity<?> generateToken(@RequestBody JwtRequest jwtRequest) throws Exception {
        System.out.println(jwtRequest);
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(jwtRequest.getUserName(), jwtRequest.getPassword()));
        }
        catch (BadCredentialsException e) {
            e.printStackTrace();
            throw new Exception("Bad Credentilas provided by user");
        }
        //fine area
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(jwtRequest.getUserName());
        String token = jwtUtil.generateToken(userDetails);
        System.out.println("JWT : " + token);
        String userName = jwtUtil.getUsernameFromToken(token);
        System.out.println("UserName : " + userName);
        return ResponseEntity.ok(new JwtResponse(token, userName));

    }
}
