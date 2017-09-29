package com.maurofokker.demo.security.voters;

import com.google.common.collect.Sets;

import java.util.Set;

public final class LockedUsers {

    private static final Set<String> lockedUsersSets = Sets.newHashSet();

    private LockedUsers() {
        //
    }

    //

    public static final boolean isLocked(final String username) {
        return lockedUsersSets.contains(username);
    }

    public static final void lock(final String username) {
        lockedUsersSets.add(username);
    }

}
