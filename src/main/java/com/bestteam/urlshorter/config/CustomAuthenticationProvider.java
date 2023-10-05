package com.bestteam.urlshorter.config;



import com.bestteam.urlshorter.auth.AuthenticationRequest;
import com.bestteam.urlshorter.models.UserUrl;
import com.bestteam.urlshorter.service.Impl.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

;


@Service
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailService;
    private final BCryptPasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails securityUser = userDetailService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authenticationToken;

        if (securityUser.isEnabled()) {
            // Proceed with password validation
            authenticationToken = checkPassword(securityUser, password);
        } else {
            // User is not enabled, return an appropriate response
            throw new DisabledException("User account is disabled.");
        }

        return authenticationToken;
    }


    private UsernamePasswordAuthenticationToken checkPassword(UserDetails user, String rowPassword) {

        if(passwordEncoder.matches(rowPassword, user.getPassword())) {
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

    public UsernamePasswordAuthenticationToken checkAuthenticationRequest(UserUrl userChat,
                                                                          AuthenticationRequest request) {

        if(passwordEncoder.matches(request.getPassword(), userChat.getPassword())) {
            UserDetails innerUser = User.builder()
                    .username(userChat.getUsername())
                    .password(userChat.getPassword())
                    .authorities(userChat.getAuthorities())
                    .build();

            return new UsernamePasswordAuthenticationToken(
                    innerUser,
                    userChat.getPassword(),
                    userChat.getAuthorities());
        } else {
            throw new BadCredentialsException("Invalid password");
        }

    }


    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }


}
