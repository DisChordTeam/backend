package com.example.dischord.user.requestDto;


import com.example.dischord.user.entity.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Getter;

@Getter
public class UserSignupRequestDto {


    @Email(message = "이메일 형식에 맞게 입력해주세요.")
    public String email;

    @NotBlank(message = "비밀번호는 필수 입력값입니다.")
    @Pattern(regexp="(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{6,20}",
            message = "비밀번호는 영문 대,소문자와 숫자, 특수기호가 적어도 1개 이상씩 포함된 6자 ~ 20자의 비밀번호여야 합니다.")
    public String password;

    @NotBlank(message = "닉네임을 입력해주세요.")
    @Size(min = 1, max = 15)
    public String nickname;




    public User toEntity(String encryptedPassword){
        return User.builder()
                .email(email)
                .password(encryptedPassword)
                .nickname(nickname)
                .build();
    }


}
