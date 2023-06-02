package com.neon.jwtsecurity.config;

import com.neon.jwtsecurity.token.Token;
import com.neon.jwtsecurity.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler
{
    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
    {
        final String authHeader = request.getHeader("Authorization");
        if(authHeader == null || !authHeader.startsWith("Bearer "))
            return;
        final String jwt = authHeader.substring(7);
        Token storedToken = tokenRepository.findByToken(jwt)
            .orElse(null);

        //If user is submitting a token that is not available within the system or an alread expired/revoked token
        if(storedToken == null || storedToken.isExpired() || storedToken.isRevoked())
        {
            try
            {
                response.getOutputStream().print("Either the submitted token is wrong or already expired/revoked");
                return;
            }
            catch (IOException e)
            {
                throw new RuntimeException(e);
            }
        }

        storedToken.setExpired(true);
        storedToken.setRevoked(true);
        tokenRepository.save(storedToken);
    }
}
