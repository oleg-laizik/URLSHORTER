package com.bestteam.urlshorter.repository;


import com.bestteam.urlshorter.auth.AuthenticationType;
import com.bestteam.urlshorter.models.UserUrl;
import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;


@Transactional
public interface UserUrlRepository extends JpaRepository<UserUrl, Long> {
//    @Query("select distinct u from UserChat u left join fetch u.roles where u.email=:email")
    @Query("select distinct u from UserUrl u where u.email = ?1")
    UserUrl findByEmailFetchRoes(String email);
    Optional<UserUrl> findByEmail(String email);
    @org.springframework.transaction.annotation.Transactional
    @Modifying
    @Query("UPDATE UserUrl u " +
            "SET u.enabled = TRUE WHERE u.email = ?1")
    int enableUserUrl(String email);

    @Modifying
    @Query("UPDATE UserUrl u SET u.authType = ?2 WHERE u.username = ?1")
    public void updateAuthenticationType(String username, AuthenticationType authType);
}
