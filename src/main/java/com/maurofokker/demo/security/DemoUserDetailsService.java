package com.maurofokker.demo.security;

import com.maurofokker.demo.persistence.UserRepository;
import com.maurofokker.demo.model.User;
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

    // needed bc there are gonna be persistence work
    // to retrieve user
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        final User user  = userRepository.findByEmail(email);
        if (user == null) {
            throw new UsernameNotFoundException("No user found with email: " + email);
        }
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), true, true, true, true, getAuthorities("ROLE_USER"));
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
