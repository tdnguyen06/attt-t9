package com.example.backend.modules.reporting;


import java.time.LocalDateTime;

public record FindingDto(
        Long id,
        String title,
        Severity severity,
        String target,
        String serviceName,
        Integer port,
        String cveId,
        String description,
        String evidence,
        String exploitationVector,
        String remediation,
        Boolean exploitAvailable,
        Boolean cisaKev,
        String exploitMaturity,
        String impact,
        String referenceUrl,
        String mitreTactic,
        String mitreTechniqueId,
        String mitreTechniqueName,
        LocalDateTime createdAt
) {}

