package com.example.backend.modules.assessment;

import com.example.backend.modules.scope.ScopeDto;

import java.time.LocalDateTime;
import java.util.List;

public record AssessmentResponse(
        Long id,
        String name,
        AssessmentType type,
        AssessmentStatus status,
        String description,
        String createdBy,
        int targetCount,
        List<String> targets,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}
