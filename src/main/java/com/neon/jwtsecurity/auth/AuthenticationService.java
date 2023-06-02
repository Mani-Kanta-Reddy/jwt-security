package com.neon.jwtsecurity.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.neon.jwtsecurity.config.JwtService;
import com.neon.jwtsecurity.token.Token;
import com.neon.jwtsecurity.token.TokenRepository;
import com.neon.jwtsecurity.token.TokenType;
import com.neon.jwtsecurity.user.Role;
import com.neon.jwtsecurity.user.User;
import com.neon.jwtsecurity.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
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
        String generatedAccessToken = jwtService.generateAccessToken(user);
        String generatedRefreshToken = jwtService.generateRefreshToken(user);
        //Associate token with the user and persist to the Token Repo
        saveUserAccessToken(user, generatedAccessToken);
        saveUserRefreshToken(user, generatedRefreshToken);
        return AuthenticationResponse.builder()
            .accessToken(generatedAccessToken)
            .refreshToken(generatedRefreshToken)
            .build();
    }

    private void saveUserAccessToken(User user, String generatedToken)
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

    private void saveUserRefreshToken(User user, String generatedToken)
    {
        Token token = Token.builder()
            .token(generatedToken)
            .tokenType(TokenType.REFRESH)
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
        String generatedAccessToken = jwtService.generateAccessToken(user);
        String generatedRefreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserAccessToken(user, generatedAccessToken);
        saveUserRefreshToken(user, generatedRefreshToken);
        return AuthenticationResponse.builder()
            .accessToken(generatedAccessToken)
            .refreshToken(generatedRefreshToken)
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

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if(authHeader == null || !authHeader.startsWith("Bearer "))
        {
            response.setStatus(400);
            response.getOutputStream().print("BAD Request");
            return;
        }

        final String refreshToken = authHeader.substring(7);
        String userEmail = jwtService.extractUsername(refreshToken);
        if(userEmail == null)
        {
            response.setStatus(400);
            response.getOutputStream().print("BAD Request");
            return;
        }
        User user = userRepository.findByEmail(userEmail).orElseThrow();
        boolean isTokenStale = tokenRepository.findByToken(refreshToken)
            .map(token -> token.isExpired() || token.isRevoked())
            .orElse(true);
        if(isTokenStale || !jwtService.isTokenValid(refreshToken, user))
        {
            response.setStatus(403);
            response.getOutputStream().print("Either the submitted token is wrong or has already expired/revoked");
            return;
        }

        final String accessToken = jwtService.generateAccessToken(user);
        revokeAllAccessTokens(user);
        saveUserAccessToken(user, accessToken);
        AuthenticationResponse authenticationResponse = AuthenticationResponse.builder()
            .accessToken(accessToken)
            .refreshToken(refreshToken)
            .build();
        response.setStatus(200);
        new ObjectMapper().writeValue(response.getOutputStream(), authenticationResponse);
    }

    private void revokeAllAccessTokens(User user)
    {
        List<Token> allValidTokensByUser = tokenRepository.finalAllValidTokensByUser(user.getId());
        if(allValidTokensByUser.isEmpty())
            return;
        List<Token> accessTokens = allValidTokensByUser
            .stream()
            .filter(token -> token.getTokenType().equals(TokenType.BEARER))
            .toList();
        if(accessTokens.isEmpty())
            return;
        accessTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(accessTokens);
    }
}
