package com.maurofokker.demo.security.providers;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        final String name = authentication.getName();
        final String password = authentication.getCredentials().toString();

        if (!supportsAuthentication(authentication)) { // check if this implementation manage authentication
            return null;
        }

        /**
         * Check authentication in 3rd party system, if its ok then return credentials in this case (from db)
         * if 3rd party system fails then must manage data to send exception. 3rd party system could send more
         * data than simple true or false and this system needs to manage that information in case of throw exception
         * Is better to control all exceptions that you can that are extends from AuthenticationException
         */
        if (doAuthenticationAgainstThirdPartySystem()) { // could do authentication in 3rd party system but in this case just return credentials
            return new UsernamePasswordAuthenticationToken(name, password, new ArrayList<>());
        } else {
            throw new BadCredentialsException("Authentication against the third party system failed");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }

    //

    private boolean doAuthenticationAgainstThirdPartySystem() {
        return true;
    }

    private boolean supportsAuthentication(Authentication authentication) {
        return true; // becausa this provider will manage authentication
    }
}
