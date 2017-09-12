package com.maurofokker.demo.service;

import com.maurofokker.demo.validation.EmailExistsException;
import com.maurofokker.demo.web.model.User;

public interface IUserService {

    User registerNewUser(User user) throws EmailExistsException;

}
