package com.example.dischord.login.token;


import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.data.annotation.Id;

@Getter
@AllArgsConstructor
public class RefreshToken {

    @Id
    private String token;

    private Long userId;
}