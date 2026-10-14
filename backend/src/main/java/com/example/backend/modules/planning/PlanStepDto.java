package com.example.backend.modules.planning;


import java.time.LocalDateTime;

public record PlanStepDto(
        Long id,
        Integer stepNumber,
        String name,
        String tool,
        String profile,
        String target,
        ImpactLevel impactLevel,
        Boolean requiresApproval,
        Boolean isApproved,
        String approvedBy,
        LocalDateTime approvedAt,
        StepStatus status,
        String description,
        String expectedOutcome,
        Long scanTaskId,
        String resultSummary
) {}
