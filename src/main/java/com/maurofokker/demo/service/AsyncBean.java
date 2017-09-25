package com.maurofokker.demo.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AsyncBean {

    private static Logger log = LoggerFactory.getLogger(AsyncBean.class);

    /**
     * SecurityContextHolder is the storage mechanism for the security information associated to the running thread
     * it uses a ThreadLocal to store de user details which hold a single context per thread, in an Async call that
     * context is lost
     * Strategy to propagate security context to new threads:
     *  Pass argument variable at startup: -Dspring.security.strategy=MODE_INHERITABLETHREADLOCAL
     *  Add to application.properties: spring.security.strategy=MODE_INHERITABLETHREADLOCAL
     *  Add programatically: SecurityContextHolder.setStrategyName("MODE_INHERITABLETHREADLOCAL")
     */
    @Async
    public void asyncCall() {
        log.info("async call... {}", SecurityContextHolder.getContext().getAuthentication());
    }
}
