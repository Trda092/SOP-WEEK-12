package com.sop.chapter10.authservice.services;

import com.sop.chapter10.authservice.entities.AuthRequest;
import com.sop.chapter10.authservice.entities.AuthResponse;
import com.sop.chapter10.authservice.entities.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthService {
    private final JwtUtil jwtUtil;

    @Autowired
    public AuthService(final JwtUtil jwtUtil){
        this.jwtUtil = jwtUtil;
    }

    public AuthResponse logIn(AuthRequest authRequest){
        User user = User.builder().id("1").email(authRequest.getEmail()).password(authRequest.getPassword()).role("admin").build();
        String accessToken = jwtUtil.generate(user, "ACCESS");
        String refreshToken = jwtUtil.generate(user, "REFRESH");
        return new AuthResponse(accessToken, refreshToken);
    }

}
