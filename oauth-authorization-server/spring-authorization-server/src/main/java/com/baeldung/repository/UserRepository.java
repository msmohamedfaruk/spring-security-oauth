package com.baeldung.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.baeldung.entity.UserInfo;

public interface UserRepository extends JpaRepository<UserInfo, Long> {

    UserInfo findByUsername(String username);
}
