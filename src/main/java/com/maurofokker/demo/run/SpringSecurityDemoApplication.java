package com.maurofokker.demo.run;

import com.maurofokker.demo.spring.*;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringSecurityDemoApplication {

	private final static Object[] CONFIGS = { // @formatter:off
			SpringSecurityDemoApplication.class,

			DemoWebConfig.class,
			DemoPersistenceJpaConfig.class,
			DemoServiceConfig.class,

			BasicSecurityConfig.class

			,
			DemoMethodSecurityConfig.class

	}; // @formatter:on

	public static void main(String[] args) {
		final SpringApplication springApplication = new SpringApplication(CONFIGS);
		springApplication.run(args);
	}
}
