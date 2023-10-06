package com.bestteam.urlshorter.auth;


import com.bestteam.urlshorter.auth.token.ConfirmationTokenService;
import com.bestteam.urlshorter.auth.token.Token;
import com.bestteam.urlshorter.auth.token.TokenRepository;
import com.bestteam.urlshorter.auth.token.TokenType;
import com.bestteam.urlshorter.models.Role;
import com.bestteam.urlshorter.models.UserUrl;
import com.bestteam.urlshorter.repository.UserUrlRepository;
import com.bestteam.urlshorter.service.Impl.UserDetailsServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@AllArgsConstructor
public class AuthenticationService {

    private final UserDetailsServiceImpl userChatDetailsService;
    private final UserUrlRepository userUrlRepository;
    private final EmailValidator emailValidator;
    private final ConfirmationTokenService confirmationTokenService;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final CustomAuthenticationProvider customAuthenticationProvider;
    public AuthenticationResponse register(RegistrationRequest request) {
        var user = UserUrl.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        var savedUser = userUrlRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }



    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        var user = userUrlRepository.findByEmail(request.getEmail())
                .orElseThrow();
        UsernamePasswordAuthenticationToken authenticationToken =
                customAuthenticationProvider.checkAuthenticationRequest(user, request);

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    public AuthenticationResponse authenticateOAuth(String userName) {
        var user = userUrlRepository.findByEmail(userName)
                .orElseThrow();

        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    private UsernamePasswordAuthenticationToken checkPassword(UserDetails user, String rowPassword) {

        if(bCryptPasswordEncoder.matches(rowPassword, user.getPassword())) {
            UserDetails innerUser = User.builder()
                    .username(user.getUsername())
                    .password(user.getPassword())
                    .authorities(user.getAuthorities())
                    .build();

            return new UsernamePasswordAuthenticationToken(innerUser, user.getPassword(), user.getAuthorities());
        } else {
            throw new BadCredentialsException("Invalid password");
        }

    }

    private void saveUserToken(UserUrl userUrl, String jwtToken) {
        var token = Token.builder()
                .userUrl(userUrl)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(UserUrl userUrl) {
        var validUserTokens = tokenRepository.findAllValidTokenByUser(userUrl.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public AuthenticationResponse refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            //TODO return some thing
            return null;
        }
        refreshToken = authHeader.substring(7);
        String accessToken = "";
        userEmail = jwtService.extractUsername(refreshToken);
        if (userEmail != null) {
            var user = this.userUrlRepository.findByEmail(userEmail)
                    .orElseThrow();
            if (jwtService.isTokenValid(refreshToken, user)) {
                accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }

        return AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }
}
