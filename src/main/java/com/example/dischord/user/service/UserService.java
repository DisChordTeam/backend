package com.example.dischord.user.service;



import com.example.dischord.global.exception.BadRequestException;
import com.example.dischord.global.exception.DuplicateException;
import com.example.dischord.user.entity.User;
import com.example.dischord.user.repository.UserRepository;
import com.example.dischord.user.requestDto.UserSignupRequestDto;
import com.example.dischord.user.responseDto.UserResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static com.example.dischord.global.exception.ExceptionCode.DUPLICATED_USER_EMAIL;
import static com.example.dischord.global.exception.ExceptionCode.NOT_FOUND_USER_ID;


@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;


    public UserResponseDto signupUser(UserSignupRequestDto requestDto) {

        checkDuplicatedEmail(requestDto.getEmail());

        User user = requestDto.toEntity(passwordEncoder.encode(requestDto.getPassword()));

        userRepository.save(user);

        return UserResponseDto.from(user);
    }

    private void checkDuplicatedEmail(final String email) {
        if (userRepository.existsByEmail(email)) {
            throw new DuplicateException(DUPLICATED_USER_EMAIL);
        }
    }

    public UserResponseDto getUser(Long userId) {

        User user = userRepository.findByIdAndDeletedAtIsNull(userId)
                .orElseThrow(() -> new BadRequestException(NOT_FOUND_USER_ID));

        return UserResponseDto.from(user);
    }

    public void deleteUser(Long userId) {

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new BadRequestException(NOT_FOUND_USER_ID));

        userRepository.delete(user);
    }


}
