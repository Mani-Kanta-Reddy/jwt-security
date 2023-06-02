package com.neon.jwtsecurity.auth;

import com.neon.jwtsecurity.config.JwtService;
import com.neon.jwtsecurity.token.Token;
import com.neon.jwtsecurity.token.TokenRepository;
import com.neon.jwtsecurity.token.TokenType;
import com.neon.jwtsecurity.user.Role;
import com.neon.jwtsecurity.user.User;
import com.neon.jwtsecurity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService
{

    private final BCryptPasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TokenRepository tokenRepository;

    public AuthenticationResponse register(RegisterRequest registerRequest)
    {
        User user = User.builder()
            .firstname(registerRequest.getFirstname())
            .lastname(registerRequest.getLastname())
            .email(registerRequest.getEmail())
            .password(passwordEncoder.encode(registerRequest.getPassword()))
            .role(Role.USER)
            .build();
        userRepository.save(user);
        String generatedToken = jwtService.generateToken(user);
        //Associate token with the user and persist to the Token Repo
        saveUserToken(user, generatedToken);
        return AuthenticationResponse.builder()
            .token(generatedToken)
            .build();
    }

    private void saveUserToken(User user, String generatedToken)
    {
        Token token = Token.builder()
            .token(generatedToken)
            .tokenType(TokenType.BEARER)
            .expired(false)
            .revoked(false)
            .user(user)
            .build();
        tokenRepository.save(token);
    }


    public AuthenticationResponse authenticate(AuthenticationRequest authRequest)
    {
        authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword())
        );
        User user = userRepository.findByEmail(authRequest.getEmail())
            .orElseThrow();
        String generatedToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, generatedToken);
        return AuthenticationResponse.builder()
            .token(generatedToken)
            .build();
    }

    private void revokeAllUserTokens(User user)
    {
        List<Token> allValidUserTokens = tokenRepository.finalAllValidTokensByUser(user.getId());
        if(allValidUserTokens.isEmpty())
            return;
        allValidUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(allValidUserTokens);
    }
}
