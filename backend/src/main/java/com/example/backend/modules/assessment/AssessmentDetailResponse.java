package com.example.backend.modules.assessment;

import com.example.backend.modules.scope.ScopeDto;

import java.time.LocalDateTime;
import java.util.List;

public record AssessmentDetailResponse(
        Long id,
        String name,
        AssessmentType type,
        AssessmentStatus status,
        String description,
        String createdBy,
        List<ScopeDto> scopes,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}
