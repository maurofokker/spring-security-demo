package com.maurofokker.demo.security;

import com.maurofokker.demo.persistence.UserRepository;
import com.maurofokker.demo.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Collection;

/**
 * Created by mauro on 9/12/17.
 */
@Transactional
@Service
public class DemoUserDetailsService implements UserDetailsService {
    private static Logger log = LoggerFactory.getLogger(DemoUserDetailsService.class);

    private static final String ROLE_USER = "ROLE_USER";

    // needed bc there are gonna be persistence work
    // to retrieve user
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        log.info("sercha username: {}", email);
        final User user  = userRepository.findByEmail(email);
        log.info("user -> {}",user.toString());
        if (user == null) {
            throw new UsernameNotFoundException("No user found with email: " + email);
        }
        //todo: put enabled as user.getEnabled() after finish feature, by the moment im disabling account validation
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), true, true, true, true, getAuthorities(ROLE_USER));
    }

    /**
     * wrapping authorities in the format spring security expects
     * add authority in collection
     * @param role
     * @return
     */
    private Collection<? extends GrantedAuthority> getAuthorities(String role) {
        return Arrays.asList(new SimpleGrantedAuthority(role));
    }
}
