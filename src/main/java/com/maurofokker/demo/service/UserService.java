package com.maurofokker.demo.service;

import com.maurofokker.demo.model.PasswordResetToken;
import com.maurofokker.demo.model.VerificationToken;
import com.maurofokker.demo.persistence.PasswordResetTokenRepository;
import com.maurofokker.demo.persistence.UserRepository;
import com.maurofokker.demo.persistence.VerificationTokenRepository;
import com.maurofokker.demo.validation.EmailExistsException;
import com.maurofokker.demo.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;

@Service
@Transactional
class UserService implements IUserService {
    private static Logger log = LoggerFactory.getLogger(UserService.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private VerificationTokenRepository verificationTokenRepository;

    @Autowired
    private PasswordResetTokenRepository passwordTokenRepository;

    @Autowired
    private PasswordEncoder encoder;

    //

    @Override
    public User findUserByEmail(final String email) {
        return userRepository.findByEmail(email);
    }

    @Override
    public User registerNewUser(final User user) throws EmailExistsException {
        if (emailExist(user.getEmail())) {
            throw new EmailExistsException("There is an account with that email address: " + user.getEmail());
        }
        user.setPassword(encoder.encode(user.getPassword())); // encode user psw
        //user.setPassword(user.getPassword());
        log.info("new user registration");
        return userRepository.save(user);
    }

    @Override
    public void createVerificationTokenForUser(final User user, final String token) {
        log.info("create verification token");
        final VerificationToken myToken = new VerificationToken(token, user);
        verificationTokenRepository.save(myToken);
    }

    @Override
    public VerificationToken getVerificationToken(final String token) {
        return verificationTokenRepository.findByToken(token);
    }

    @Override
    public void saveRegisteredUser(final User user) {
        userRepository.save(user);
    }

    @Override
    public void changeUserPassword(final User user, final String password) {
        //user.setPassword(password);
        user.setPassword(encoder.encode(user.getPassword())); // encode user psw
        userRepository.save(user);
    }

    @Override
    public void createPasswordResetTokenForUser(final User user, final String token) {
        final PasswordResetToken myToken = new PasswordResetToken(token, user);
        passwordTokenRepository.save(myToken);
    }

    @Override
    public PasswordResetToken getPasswordResetToken(final String token) {
        return passwordTokenRepository.findByToken(token);
    }


    //

    private boolean emailExist(String email) {
        final User user = userRepository.findByEmail(email);
        return user != null;
    }

}
