package com.maurofokker.demo.web.controller;

import com.maurofokker.demo.model.VerificationToken;
import com.maurofokker.demo.registration.OnRegistrationCompleteEvent;
import com.maurofokker.demo.service.IUserService;
import com.maurofokker.demo.validation.EmailExistsException;
import com.maurofokker.demo.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.Calendar;

@Controller
class RegistrationController {
    private static Logger log = LoggerFactory.getLogger(RegistrationController.class);

    @Autowired
    private IUserService userService;

    @Autowired
    private ApplicationEventPublisher eventPublisher;

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
    public ModelAndView registerUser(@Valid final User user, final BindingResult result, final HttpServletRequest request) {
        log.info("user registration received!...");
        if (result.hasErrors()) {
            return new ModelAndView("registrationPage", "user", user);
        }
        try {
            final User registered = userService.registerNewUser(user);

            final String appUrl = "http://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath();
            eventPublisher.publishEvent(new OnRegistrationCompleteEvent(registered, appUrl));
        } catch (EmailExistsException e) {
            result.addError(new FieldError("user", "email", e.getMessage()));
            return new ModelAndView("registrationPage", "user", user);
        }
        return new ModelAndView("/loginPage");
    }

    @RequestMapping(value = "/registrationConfirm")
    public ModelAndView confirmRegistration(final Model model, @RequestParam("token") final String token, final RedirectAttributes redirectAttributes) {
        final VerificationToken verificationToken = userService.getVerificationToken(token);
        if (verificationToken == null) {
            redirectAttributes.addFlashAttribute("errorMessage", "Invalid account confirmation token.");
            return new ModelAndView("redirect:/login");
        }

        final User user = verificationToken.getUser();
        final Calendar cal = Calendar.getInstance();
        if ((verificationToken.getExpiryDate().getTime() - cal.getTime().getTime()) <= 0) {
            redirectAttributes.addFlashAttribute("errorMessage", "Your registration token has expired. Please register again.");
            return new ModelAndView("redirect:/login");
        }

        user.setEnabled(true);
        userService.saveRegisteredUser(user);
        redirectAttributes.addFlashAttribute("message", "Your account verified successfully");
        return new ModelAndView("redirect:/login");
    }

}
