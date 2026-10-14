package com.example.backend.modules.reporting;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AssessmentReportRepository extends JpaRepository<AssessmentReport, Long> {
    Optional<AssessmentReport> findTopByAssessmentIdOrderByGeneratedAtDesc(Long assessmentId);
    List<AssessmentReport> findByAssessmentId(Long assessmentId);
}
