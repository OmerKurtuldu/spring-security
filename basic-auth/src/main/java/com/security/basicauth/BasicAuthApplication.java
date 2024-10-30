package com.security.basicauth;

import com.security.basicauth.dto.CreateUserRequest;
import com.security.basicauth.model.Role;
import com.security.basicauth.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Set;

@SpringBootApplication
public class BasicAuthApplication implements CommandLineRunner {

    private final UserService userService;

    public BasicAuthApplication(UserService userService) {
        this.userService = userService;
    }

    public static void main(String[] args) {
        SpringApplication.run(BasicAuthApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        createDummyData();
    }

    private void createDummyData() {
        CreateUserRequest request = CreateUserRequest.builder()
                .name("Murat")
                .username("murat")
                .password("pass")
                .authorities(Set.of(Role.ROLE_USER))
                .build();
        userService.createUser(request);

        CreateUserRequest request2 = CreateUserRequest.builder()
                .name("Omer")
                .username("omer")
                .password("pass")
                .authorities(Set.of(Role.ROLE_OMER))
                .build();
        userService.createUser(request2);

        CreateUserRequest request3 = CreateUserRequest.builder()
                .name("No name")
                .username("admin")
                .password("pass")
                .authorities(Set.of(Role.ROLE_ADMIN))
                .build();
        userService.createUser(request3);
    }


}
