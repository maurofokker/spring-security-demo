package com.maurofokker.demo.security.voters;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

import java.util.Collection;

/**
 * To lock users out and have that lockout apply in real-time (not after a login)
 * The need for this kind of real-time lockout is simple - if a user is locked out,
 * then they’re a serious security concern so we need to make sure that their current session cannot be used to do any damage.
 */
public class RealTimeLockVoter implements AccessDecisionVoter<Object> {

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        if (LockedUsers.isLocked(authentication.getName())) {
            return ACCESS_DENIED;
        }

        return ACCESS_GRANTED;
    }
    
}
