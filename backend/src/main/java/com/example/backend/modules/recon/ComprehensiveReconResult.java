package com.example.backend.modules.recon;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ComprehensiveReconResult {
    private String target;
    @com.fasterxml.jackson.annotation.JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
    private LocalDateTime scannedAt;
    private DnsReconResult dns;
    private WhoisResult whois;
    private HttpSecurityScanResult httpSecurity;
    private WebDirectoryScanResult webDirectories;
    private TechStackScanResult techStack;
    private VulnerabilityAuditResult vulnerabilityAudit;
    private BloodhoundAuditSummaryDto bloodhoundAudit;
    private AttackSurfaceTreeDto attackTree;
    private String executiveSummary;
    private long totalDurationMs;
}
