package com.neon.jwtsecurity.auth;

import com.neon.jwtsecurity.config.JwtService;
import com.neon.jwtsecurity.user.Role;
import com.neon.jwtsecurity.user.User;
import com.neon.jwtsecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService
{

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository repository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest registerRequest)
    {
        User user = User.builder()
            .firstname(registerRequest.getFirstname())
            .lastname(registerRequest.getLastname())
            .email(registerRequest.getEmail())
            .password(passwordEncoder.encode(registerRequest.getPassword()))
            .role(Role.USER)
            .build();
        repository.save(user);
        String generatedToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
            .token(generatedToken)
            .build();
    }


    public AuthenticationResponse authenticate(AuthenticationRequest authRequest)
    {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword())
        );
        User user = repository.findByEmail(authRequest.getEmail())
            .orElseThrow();
        String generatedToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
            .token(generatedToken)
            .build();
    }
}
