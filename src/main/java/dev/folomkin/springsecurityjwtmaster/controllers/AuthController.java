package dev.folomkin.springsecurityjwtmaster.controllers;

import dev.folomkin.springsecurityjwtmaster.dtos.JwtRequest;
import dev.folomkin.springsecurityjwtmaster.dtos.RegistrationUserDto;
import dev.folomkin.springsecurityjwtmaster.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/auth")
    public ResponseEntity<?> createAuthToken(@RequestBody JwtRequest authRequest) {
        return authService.login(authRequest);
    }

    @PostMapping("/registration")
    public ResponseEntity<?> registerUser(@RequestBody RegistrationUserDto registrationUserDto) {
        return authService.registerUser(registrationUserDto);
    }
}
