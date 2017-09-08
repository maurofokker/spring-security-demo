package com.maurofokker.demo.spring;

import com.maurofokker.demo.persistence.InMemoryUserRepository;
import com.maurofokker.demo.persistence.UserRepository;
import com.maurofokker.demo.web.model.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;

@Configuration
@ComponentScan({"com.maurofokker.demo.web"})
public class DemoWebConfig {

    public DemoWebConfig() {
        super();
    }

    @Bean
    public UserRepository userRepository() {
        return new InMemoryUserRepository();
    }

    @Bean
    public Converter<String, User> messageConverter() {
        return new Converter<String, User>() {
            @Override
            public User convert(String id) {
                return userRepository().findUser(Long.valueOf(id));
            }
        };
    }

}
