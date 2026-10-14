package com.example.backend.modules.planning;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PlanStepRepository extends JpaRepository<PlanStep, Long> {
    List<PlanStep> findByPlanIdOrderByStepNumberAsc(Long planId);
    List<PlanStep> findByPlanIdAndStatus(Long planId, StepStatus status);
}
