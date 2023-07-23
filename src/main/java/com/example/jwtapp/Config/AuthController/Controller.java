package com.example.jwtapp.Config.AuthController;

import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@AllArgsConstructor

public class Controller {

    private final AuthenticationService authenticationService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationReprocess> register(
            @RequestBody RegisterRequest registerBody
    ) {
        return ResponseEntity.ok(authenticationService.register(registerBody));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationReprocess> authenticate(
            @RequestBody AuthenticationRequest registerBody
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(registerBody));
    }
}
