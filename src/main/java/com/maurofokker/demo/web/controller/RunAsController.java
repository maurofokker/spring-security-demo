package com.maurofokker.demo.web.controller;

import com.maurofokker.demo.service.RunAsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Created by mauro on 9/20/17.
 */
@Controller
@RequestMapping("/runas")
public class RunAsController {

    @Autowired
    private RunAsService runAsService;

    @Secured({ "ROLE_USER", "RUN_AS_REPORTER" })
    @RequestMapping
    @ResponseBody
    public String tryRunAs() {
        final Authentication auth = runAsService.getCurrentUser();
        auth.getAuthorities().forEach(a -> System.out.println(a.getAuthority()));
        return "Current User Authorities inside this RunAS method only " + auth.getAuthorities().toString();
    }

}
