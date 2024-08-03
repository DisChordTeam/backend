package com.example.dischord.global.exception;


import lombok.Getter;

@Getter
public class TokenExpiredException extends RuntimeException{

    private final int code;
    private final String message;

    public TokenExpiredException(final ExceptionCode exceptionCode) {
        this.code = exceptionCode.getCode();
        this.message = exceptionCode.getMessage();
    }
}
