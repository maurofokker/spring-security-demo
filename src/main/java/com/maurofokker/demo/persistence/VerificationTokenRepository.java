package com.maurofokker.demo.persistence;

import com.maurofokker.demo.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Created by mauro on 9/12/17.
 */
public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    VerificationToken findByToken(String token);

}
