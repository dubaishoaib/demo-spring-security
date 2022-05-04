package com.example.demo.spring.security.dao;

import com.example.demo.spring.security.auth.ApplicationUser;

import java.util.Optional;

public interface ApplicationUserDao {

    Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
