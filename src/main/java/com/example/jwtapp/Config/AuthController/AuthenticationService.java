package com.example.jwtapp.Config.AuthController;

import com.example.jwtapp.Config.JWService;
import com.example.jwtapp.User.Repository.UserRepository;
import com.example.jwtapp.User.Role;
import com.example.jwtapp.User.User;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final JWService jwService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationReprocess register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        repository.save(user);

        var jwtToken = jwService.generateToken(user);

        return AuthenticationReprocess.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationReprocess authenticate(AuthenticationRequest request) {
        new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword());

        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        var jwtToken = jwService.generateToken(user);
        return AuthenticationReprocess.builder()
                .token(jwtToken)
                .build();
    }
}
