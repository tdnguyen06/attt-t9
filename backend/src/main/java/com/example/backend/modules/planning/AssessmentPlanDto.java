package com.example.backend.modules.planning;


import java.time.LocalDateTime;
import java.util.List;

public record AssessmentPlanDto(
        Long id,
        Long assessmentId,
        String title,
        String summary,
        String riskAssessment,
        PlanStatus status,
        List<PlanStepDto> steps,
        int totalSteps,
        int pendingApprovalSteps,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}
