package com.example.backend.modules.reporting;


import java.time.LocalDateTime;
import java.util.List;

public record AssessmentReportDto(
        Long id,
        Long assessmentId,
        String title,
        String executiveSummary,
        Severity overallRisk,
        Integer totalFindings,
        Integer criticalCount,
        Integer highCount,
        Integer mediumCount,
        Integer lowCount,
        Integer infoCount,
        String recommendations,
        String generatedBy,
        List<FindingDto> findings,
        LocalDateTime generatedAt
) {}
