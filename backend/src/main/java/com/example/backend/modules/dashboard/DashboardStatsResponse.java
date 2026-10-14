package com.example.backend.modules.dashboard;

import java.time.LocalDateTime;
import java.util.List;

public record DashboardStatsResponse(
        long totalAssessments,
        long inProgressAssessments,
        long completedAssessments,
        long totalScans,
        long completedScans,
        long totalFindings,
        long totalAuditLogs,
        List<RecentIncidentDto> recentIncidents,
        List<ServiceStatusDto> services
) {
    public record RecentIncidentDto(
            Long id,
            String action,
            String moduleName,
            String target,
            String decision,
            String resultStatus,
            String requester,
            String ipAddress,
            LocalDateTime createdAt
    ) {}

    public record ServiceStatusDto(
            String name,
            String description,
            String status,
            String badgeType
    ) {}
}
