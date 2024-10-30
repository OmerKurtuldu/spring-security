package com.security.basicauth.repository;

import com.security.basicauth.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional findByUsername(String userName);

}
