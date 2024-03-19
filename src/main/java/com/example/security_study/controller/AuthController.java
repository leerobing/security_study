package com.example.security_study.controller;

import com.example.security_study.domain.Member;
import com.example.security_study.dto.AuthJoinRequestDto;
import com.example.security_study.dto.AuthLoginRequestDto;
import com.example.security_study.security.TokenInfo;
import com.example.security_study.service.AuthService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/join")
    public ResponseEntity join(@RequestBody AuthJoinRequestDto authJoinRequestDto) {


        authService.join(authJoinRequestDto);

        return new ResponseEntity(HttpStatus.OK);

    }

    @PostMapping("/login") //로그인
    public TokenInfo login(@RequestBody AuthLoginRequestDto authLoginRequestDto) {
        String memberId = authLoginRequestDto.getMemberId();
        String password = authLoginRequestDto.getPassword();
        TokenInfo tokenInfo = authService.login(memberId, password);
        return tokenInfo;
    }
}
