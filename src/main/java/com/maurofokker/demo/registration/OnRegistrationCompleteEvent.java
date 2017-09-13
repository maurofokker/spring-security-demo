package com.maurofokker.demo.registration;

import com.maurofokker.demo.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;

/**
 * Created by mauro on 9/12/17.
 */
public class OnRegistrationCompleteEvent extends ApplicationEvent {
    private static Logger log = LoggerFactory.getLogger(OnRegistrationCompleteEvent.class);

    private final String appUrl;
    private final User user;

    public OnRegistrationCompleteEvent(final User user, final String appUrl) {
        super(user);
        log.info("Event triggered");
        this.user = user;
        this.appUrl = appUrl;
    }

    //

    public String getAppUrl() {
        return appUrl;
    }

    public User getUser() {
        return user;
    }

}
