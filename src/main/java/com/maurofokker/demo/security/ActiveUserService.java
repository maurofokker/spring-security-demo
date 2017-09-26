package com.maurofokker.demo.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ActiveUserService {
    private static Logger log = LoggerFactory.getLogger(ActiveUserService.class);

    @Autowired
    private SessionRegistry sessionRegistry; // already wired in BasicSecurityConfig

    public List<String> getAllActiveUsers() {
        //List<User> principals = sessionRegistry.getAllPrincipals(); // return List<Object> (parent) and cannot be casted to List<User> (child)
        List<Object> principals = sessionRegistry.getAllPrincipals();
        log.info("Principals list of objects -> {}", principals);
        User[] users = principals.toArray(new User[principals.size()]); // convert to array of Users
        log.info("Users array --> {}", users);

        return Arrays.stream(users)
                .filter(u -> !sessionRegistry.getAllSessions(u, false).isEmpty()) // get active sessions from all sessiones
                .map(u -> u.getUsername()) // get usernames
                .collect(Collectors.toList())
        ;
    }
}
