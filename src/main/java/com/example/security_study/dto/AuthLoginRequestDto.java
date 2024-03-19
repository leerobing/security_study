package com.example.security_study.dto;

import lombok.Data;

@Data
public class AuthLoginRequestDto {
    private String memberId;
    private String password;
}
