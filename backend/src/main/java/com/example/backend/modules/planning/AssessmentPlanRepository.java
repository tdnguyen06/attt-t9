package com.example.backend.modules.planning;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AssessmentPlanRepository extends JpaRepository<AssessmentPlan, Long> {
    Optional<AssessmentPlan> findTopByAssessmentIdOrderByCreatedAtDesc(Long assessmentId);
    List<AssessmentPlan> findByAssessmentId(Long assessmentId);
}
