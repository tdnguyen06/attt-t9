package com.example.backend.modules.scan;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanTaskRepository extends JpaRepository<ScanTask, Long> {
    List<ScanTask> findByAssessmentIdOrderByCreatedAtDesc(Long assessmentId);
    List<ScanTask> findAllByOrderByCreatedAtDesc();
}
