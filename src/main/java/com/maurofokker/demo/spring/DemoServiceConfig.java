package com.maurofokker.demo.spring;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan({ "com.maurofokker.demo.service", "com.maurofokker.demo.registration" })
public class DemoServiceConfig {
}
