package com.security.jwttoken.repository;


import com.security.jwttoken.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional findByUsername(String userName);

}
