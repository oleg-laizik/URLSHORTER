package com.bestteam.urlshorter.config;



import com.bestteam.urlshorter.auth.CustomAuthenticationProvider;
import com.bestteam.urlshorter.repository.UserUrlRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

  private final CustomAuthenticationProvider authProvider;

  private final UserUrlRepository userUrlRepository;
  private final PasswordEncoder passwordEncoder;


  @Bean
  public UserDetailsService userDetailsService() {
    return username -> userUrlRepository.findByEmail(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
  }

//  @Bean
//  public AuthenticationProvider authenticationProvider() {
//    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
//    authProvider.setUserDetailsService(userDetailsService());
//    authProvider.setPasswordEncoder(passwordEncoder());
//    return authProvider;
//  }




}
