package com.maurofokker.demo.persistence;

import com.maurofokker.demo.web.model.User;

public interface UserRepository {

    Iterable<User> findAll();

    User save(User user);

    User findUser(Long id);

    void deleteUser(Long id);

}
