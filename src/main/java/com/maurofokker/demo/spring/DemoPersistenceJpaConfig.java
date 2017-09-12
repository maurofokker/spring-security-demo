package com.maurofokker.demo.spring;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories(basePackages = "com.maurofokker.demo.persistence")
@EntityScan("com.maurofokker.demo.web.model")
public class DemoPersistenceJpaConfig {
}
