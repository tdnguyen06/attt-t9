package com.example.backend.modules.recon;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/recon")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ReconController {

    private final ReconService reconService;

    @PostMapping("/dns")
    public ResponseEntity<DnsReconResult> performDnsRecon(@Valid @RequestBody ReconRequest request) {
        return ResponseEntity.ok(reconService.performDnsRecon(request.getTarget()));
    }

    @PostMapping("/whois")
    public ResponseEntity<WhoisResult> performWhois(@Valid @RequestBody ReconRequest request) {
        return ResponseEntity.ok(reconService.performWhois(request.getTarget()));
    }

    @PostMapping("/http-headers")
    public ResponseEntity<HttpSecurityScanResult> scanHttpHeaders(@Valid @RequestBody ReconRequest request) {
        return ResponseEntity.ok(reconService.scanHttpSecurity(request.getTarget()));
    }

    @PostMapping("/web-directories")
    public ResponseEntity<WebDirectoryScanResult> scanWebDirectories(@Valid @RequestBody ReconRequest request) {
        return ResponseEntity.ok(reconService.scanWebDirectories(request.getTarget()));
    }

    @PostMapping("/tech-stack")
    public ResponseEntity<TechStackScanResult> detectTechStack(@Valid @RequestBody ReconRequest request) {
        return ResponseEntity.ok(reconService.detectTechStack(request.getTarget()));
    }

    @PostMapping("/vulnerabilities")
    public ResponseEntity<VulnerabilityAuditResult> auditVulnerabilities(@Valid @RequestBody ReconRequest request) {
        return ResponseEntity.ok(reconService.auditVulnerabilities(request.getTarget()));
    }

    @PostMapping({"/comprehensive", "/all"})
    public ResponseEntity<ComprehensiveReconResult> performComprehensiveRecon(@Valid @RequestBody ReconRequest request) {
        return ResponseEntity.ok(reconService.performComprehensiveRecon(request.getTarget()));
    }
}
