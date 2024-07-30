package com.example.dischord.global.response;

import com.example.dischord.global.exception.ExceptionResponse;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;

import java.util.HashMap;
import java.util.List;
import java.util.Map;


@NoArgsConstructor
@Getter
@Setter
public class ApiResponse<T> {


    private int code;
    private String message;
    private T data;

    public static <T> ApiResponse<T> ok(T data) {

        return new ApiResponse<>(200, null, data);
    }

    public static ApiResponse<?> ok() {

        return new ApiResponse<>(200, null, null);
    }

    public static ApiResponse<ExceptionResponse> error(int errorCode, String message) {

        return new ApiResponse<>(errorCode, message, null);
    }


    public ApiResponse(int code, String message, T data) {
        this.code = code;
        this.message = message;
        this.data = data;
    }

}

