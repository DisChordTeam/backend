package com.example.dischord.global.jwt;

import lombok.*;

@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class VerifyResult {
    private boolean success;
    private String email;
}