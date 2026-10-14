package com.example.backend.modules.recon;

public interface ReconService {

    DnsReconResult performDnsRecon(String target);

    WhoisResult performWhois(String target);

    HttpSecurityScanResult scanHttpSecurity(String target);

    WebDirectoryScanResult scanWebDirectories(String target);

    TechStackScanResult detectTechStack(String target);

    VulnerabilityAuditResult auditVulnerabilities(String target);

    ComprehensiveReconResult performComprehensiveRecon(String target);
}
