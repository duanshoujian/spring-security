package com.example.security;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@SpringBootTest
class SecurityApplicationTests {

	@Test
	void contextLoads() {
		for(int i=0;i<10;i++){
			BCryptPasswordEncoder bcencoder = new BCryptPasswordEncoder();
			System.out.println(bcencoder.encode("123"));

		}
	}

}
