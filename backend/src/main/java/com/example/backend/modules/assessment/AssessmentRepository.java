package com.example.backend.modules.assessment;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface AssessmentRepository extends JpaRepository<Assessment, Long> {
    List<Assessment> findByStatus(AssessmentStatus status);
    List<Assessment> findAllByOrderByCreatedAtDesc();
}
