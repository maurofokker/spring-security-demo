package com.maurofokker.demo.service;

import com.maurofokker.demo.model.PasswordResetToken;
import com.maurofokker.demo.model.VerificationToken;
import com.maurofokker.demo.validation.EmailExistsException;
import com.maurofokker.demo.model.User;

public interface IUserService {

    User findUserByEmail(final String email);

    User registerNewUser(User user) throws EmailExistsException;

    void createVerificationTokenForUser(User user, String token);

    VerificationToken getVerificationToken(String token);

    void saveRegisteredUser(User user);

    void changeUserPassword(User user, String password);

    void createPasswordResetTokenForUser(User user, String token);

    PasswordResetToken getPasswordResetToken(String token);

}
