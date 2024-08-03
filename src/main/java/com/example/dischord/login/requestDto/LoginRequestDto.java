package com.example.dischord.login.requestDto;


import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;


@Getter
public class LoginRequestDto {

    @Email(message = "이메일 형식에 맞게 입력해주세요.")
    private String email;

    @NotBlank(message = "비밀번호를 입력해주세요.")
    private String password;

    private String refreshToken;

}
