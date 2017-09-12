package com.maurofokker.demo.web.controller;

import com.maurofokker.demo.service.IUserService;
import com.maurofokker.demo.validation.EmailExistsException;
import com.maurofokker.demo.web.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.validation.Valid;

@Controller
class RegistrationController {

    @Autowired
    private IUserService userService;

    //

    /**
     * ensure the links btw /signup and registrationPage.html template
     * @return a User in the model
     */
    @RequestMapping(value = "signup")
    public ModelAndView registrationForm() {
        return new ModelAndView("registrationPage", "user", new User());
    }

    /**
     * Implements the register operation
     *
     * @param user
     * @param result
     * @return
     */
    @RequestMapping(value = "user/register")
    public ModelAndView registerUser(@Valid final User user, final BindingResult result) {
        if (result.hasErrors()) {
            return new ModelAndView("registrationPage", "user", user);
        }
        try {
            userService.registerNewUser(user);
        } catch (EmailExistsException e) {
            result.addError(new FieldError("user", "email", e.getMessage()));
            return new ModelAndView("registrationPage", "user", user);
        }
        return new ModelAndView("redirect:/login");
    }

}
