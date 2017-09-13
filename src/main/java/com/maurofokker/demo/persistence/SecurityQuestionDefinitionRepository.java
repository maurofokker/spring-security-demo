package com.maurofokker.demo.persistence;

import com.maurofokker.demo.model.SecurityQuestionDefinition;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityQuestionDefinitionRepository extends JpaRepository<SecurityQuestionDefinition, Long> {

}