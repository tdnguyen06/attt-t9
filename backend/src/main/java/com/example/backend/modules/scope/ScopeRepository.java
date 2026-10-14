package com.example.backend.modules.scope;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScopeRepository extends JpaRepository<Scope, Long> {
    List<Scope> findByAssessmentId(Long assessmentId);
}
