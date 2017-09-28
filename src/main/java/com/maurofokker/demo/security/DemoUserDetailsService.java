package com.maurofokker.demo.security;

import com.maurofokker.demo.model.Role;
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
import java.util.stream.Collectors;

/**
 * Created by mauro on 9/12/17.
 */
@Transactional
@Service
public class DemoUserDetailsService implements UserDetailsService {
    private static Logger log = LoggerFactory.getLogger(DemoUserDetailsService.class);

    // needed bc there are gonna be persistence work
    // to retrieve user
    @Autowired
    private UserRepository userRepository;

    public DemoUserDetailsService() {
        super();
    }

    @Override
    public UserDetails loadUserByUsername(final String email) throws UsernameNotFoundException {
        log.info("sercha username: {}", email);
        final User user  = userRepository.findByEmail(email);
        log.info("user -> {}",user.toString());
        if (user == null) {
            throw new UsernameNotFoundException("No user found with email: " + email);
        }
        //todo: put enabled as user.getEnabled() after finish feature, by the moment im disabling account validation
        return new org.springframework.security.core.userdetails.User(user.getEmail(), user.getPassword(), true, true, true, true, getAuthorities(user.getRoles()));
    }

    /**
     * wrapping authorities in the format spring security expects
     * add authority in collection
     * @param roles
     * @return
     */
    public final Collection<? extends GrantedAuthority> getAuthorities(final Collection<Role> roles) {
        return roles.stream()
                .flatMap(role -> role.getPrivileges().stream())
                .map(p -> new SimpleGrantedAuthority(p.getName()))
                .collect(Collectors.toList());
    }
}
