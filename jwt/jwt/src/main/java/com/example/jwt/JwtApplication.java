package com.example.jwt;

import com.example.jwt.domain.Role;
import com.example.jwt.domain.User;
import com.example.jwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class JwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}

	@Bean
	CommandLineRunner runner(UserService userService){
		return args -> {
			userService.saveRole(new Role(null, "ROLE_USER"));
			userService.saveRole(new Role(null, "ROLE_MANAGER"));
			userService.saveRole(new Role(null, "ROLE_ADMIN"));
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
			userService.saveUser(new User(null, "john", "john", "john",new ArrayList<>()));
			userService.saveUser(new User(null, "will", "will", "will",new ArrayList<>()));
			userService.saveUser(new User(null, "joseph", "joseph", "joseph",new ArrayList<>()));
			userService.saveUser(new User(null, "jotaro", "jotaro", "jotaro",new ArrayList<>()));
			userService.addRoleToUser("john", "ROLE_USER");
			userService.addRoleToUser("will","ROLE_MANAGER");
			userService.addRoleToUser("joseph", "ROLE_ADMIN");
			userService.addRoleToUser("jotaro", "ROLE_SUPER_ADMIN");

		};
	}

}
