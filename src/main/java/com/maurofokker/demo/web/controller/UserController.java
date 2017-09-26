package com.maurofokker.demo.web.controller;

import com.maurofokker.demo.persistence.UserRepository;
import com.maurofokker.demo.security.ActiveUserService;
import com.maurofokker.demo.service.AsyncBean;
import com.maurofokker.demo.service.IUserService;
import com.maurofokker.demo.validation.EmailExistsException;
import com.maurofokker.demo.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.validation.Valid;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/user")
public class UserController {
    private static Logger log = LoggerFactory.getLogger(UserController.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private IUserService userService;

    @Autowired
    private AsyncBean asyncBean;

    @Autowired
    private ActiveUserService activeUserService;

    //

    @RequestMapping
    public ModelAndView list() {
        asyncBean.asyncCall(); // call to asyng method to see what happen with spring security context

        // return just active users
        List<User> users = activeUserService.getAllActiveUsers().stream()
                .map(s -> userRepository.findByEmail(s)).collect(Collectors.toList());

        log.info("users -> {}", users);
        //Iterable<User> users = this.userRepository.findAll();
        return new ModelAndView("users/list", "users", users);
    }

    @RequestMapping("{id}")
    public ModelAndView view(@PathVariable("id") final User user) {
        return new ModelAndView("users/view", "user", user);
    }

    @RequestMapping(params = "form", method = RequestMethod.GET)
    public String createForm(@ModelAttribute User user) {
        return "users/form";
    }

    @RequestMapping(method = RequestMethod.POST)
    public ModelAndView create(@Valid final User user, BindingResult result, RedirectAttributes redirect) {
        if (result.hasErrors()) {
            return new ModelAndView("users/form", "formErrors", result.getAllErrors());
        }
        try {
            userService.registerNewUser(user);
        } catch (EmailExistsException e) {
            result.addError(new FieldError("user", "email", e.getMessage()));
            return new ModelAndView("users/form", "user", user);
        }
        redirect.addFlashAttribute("globalMessage", "Successfully created a new user");
        return new ModelAndView("redirect:/user/{user.id}", "user.id", user.getId());
    }

    @RequestMapping("foo")
    public String foo() {
        throw new RuntimeException("Expected exception in controller");
    }

    @RequestMapping(value = "delete/{id}")
    public ModelAndView delete(@PathVariable("id") Long id) {
        this.userRepository.delete(id);
        return new ModelAndView("redirect:/user/");
    }

    @RequestMapping(value = "modify/{id}", method = RequestMethod.GET)
    public ModelAndView modifyForm(@PathVariable("id") User user) {
        return new ModelAndView("users/form", "user", user);
    }

}
