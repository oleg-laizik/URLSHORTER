package com.bestteam.urlshorter.service.Impl;


import com.bestteam.urlshorter.auth.AuthenticationType;
import com.bestteam.urlshorter.auth.token.ConfirmationToken;
import com.bestteam.urlshorter.auth.token.ConfirmationTokenService;
import com.bestteam.urlshorter.models.Role;
import com.bestteam.urlshorter.models.UserUrl;
import com.bestteam.urlshorter.repository.UserUrlRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

import static com.bestteam.urlshorter.models.Constants.ADMIN_PASSWORD;
import static com.bestteam.urlshorter.models.Constants.ADMIN_USERNAME;



@Slf4j
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
	private final UserUrlRepository userUrlRepository;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;
	private final ConfirmationTokenService confirmationTokenService;

	private static final String USER_NOT_FOUND = "Could not find user with email %s ";

	@Value(value = "${" + ADMIN_USERNAME + "}")
	private String username;

	@Value(value = "${" + ADMIN_PASSWORD + "}")
	private String password;


	@Override
	public UserDetails loadUserByUsername(String email)
			throws UsernameNotFoundException {
		
		return userUrlRepository.findByEmail(email)
				.orElseThrow(() ->
						new UsernameNotFoundException(
								String.format(USER_NOT_FOUND, email)));
	}

	public void processOAuthPostLogin(String username) {
		UserUrl existUserChat = userUrlRepository.findByEmailFetchRoes(username);

		if (existUserChat == null) {
			UserUrl newUserChat = new UserUrl();
			newUserChat.setUsername(username);
			newUserChat.setEmail(username);
			newUserChat.setAuthType(AuthenticationType.GOOGLE);
			newUserChat.setRole(Role.USER);
			newUserChat.setEnabled(true);

			userUrlRepository.save(newUserChat);

			System.out.println("Created new userChat: " + username);
		}
	}

	public String signUpUser(UserUrl userUrl) {
		boolean userExists = userUrlRepository
				.findByEmail(userUrl.getEmail())
				.isPresent();

		if (userExists) {
			// TODO check of attributes are the same and
			// TODO if email not confirmed send confirmation email.

			return "Email already taken";
		}

		String encodedPassword = bCryptPasswordEncoder
				.encode(userUrl.getPassword());

		userUrl.setPassword(encodedPassword);

		userUrlRepository.save(userUrl);

		String token = UUID.randomUUID().toString();

		ConfirmationToken confirmationToken = new ConfirmationToken(
				token,
				LocalDateTime.now(),
				LocalDateTime.now().plusMinutes(15),
				userUrl
		);

		confirmationTokenService.saveConfirmationToken(
				confirmationToken);

//        TODO: SEND EMAIL

		return token;
	}

	public int enableUserUrl(String email) {
		return userUrlRepository.enableUserUrl(email);
	}
}
