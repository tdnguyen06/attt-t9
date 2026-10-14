package com.example.backend.modules.reporting;

import com.example.backend.modules.assessment.Assessment;
import com.example.backend.modules.assessment.AssessmentStatus;
import com.example.backend.modules.assessment.AssessmentRepository;
import com.example.backend.modules.audit.AuditDecision;
import com.example.backend.modules.audit.AuditLogService;
import com.example.backend.modules.llm.LlmAnalysisResult;
import com.example.backend.modules.llm.LlmService;
import com.example.backend.modules.scan.HostResult;
import com.example.backend.modules.scan.NmapScanResult;
import com.example.backend.modules.scan.PortResult;
import com.example.backend.modules.scan.ScanTask;
import com.example.backend.modules.scan.NmapXmlParser;
import com.example.backend.modules.scan.ScanService;
import com.example.backend.modules.recon.BloodhoundAuditSummaryDto;
import com.example.backend.modules.recon.BloodhoundFilterService;
import com.example.backend.modules.recon.BloodhoundFindingDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReportingServiceImpl implements ReportingService {

    private final AssessmentReportRepository reportRepository;
    private final VulnerabilityFindingRepository findingRepository;
    private final AssessmentRepository assessmentRepository;
    private final ScanService scanService;
    private final NmapXmlParser nmapXmlParser;
    private final LlmService llmService;
    private final AuditLogService auditLogService;
    private final BloodhoundFilterService bloodhoundFilterService;
    private final com.example.backend.modules.recon.CveIntelligenceService cveIntelligenceService;
    private final com.example.backend.modules.mitre.MitreMappingService mitreMappingService;

    @Override
    @Transactional
    public AssessmentReportDto generateReport(Long assessmentId, GenerateReportRequest request) {
        log.info("Generating security assessment report for ID: {}", assessmentId);

        Assessment assessment = assessmentRepository.findById(assessmentId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy phiên kiểm thử ID: " + assessmentId));

        List<ScanTask> scanTasks = scanService.getTasksByAssessmentId(assessmentId);

        List<VulnerabilityFinding> findings = new ArrayList<>();
        StringBuilder scanSummaryBuilder = new StringBuilder();

        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper()
                .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        for (ScanTask task : scanTasks) {
            if (task.getRawXmlOutput() != null && !task.getRawXmlOutput().isEmpty()) {
                NmapScanResult scanResult = nmapXmlParser.parse(task.getRawXmlOutput());

                for (HostResult host : scanResult.hosts()) {
                    scanSummaryBuilder.append("Host: ").append(host.ipAddress()).append(" (").append(host.state()).append(")\n");

                    for (PortResult port : host.ports()) {
                        scanSummaryBuilder.append("  - Port ").append(port.portId()).append("/").append(port.protocol())
                                .append(" [").append(port.state()).append("] ").append(port.serviceName())
                                .append(" ").append(port.product()).append(" ").append(port.version()).append("\n");

                        evaluatePortRisk(host.ipAddress(), port, findings);
                    }
                }
            }

            if (task.getParsedSummary() != null && !task.getParsedSummary().isBlank()) {
                try {
                    com.fasterxml.jackson.databind.JsonNode rootNode = mapper.readTree(task.getParsedSummary());
                    
                    // 1. Kiểm tra nếu có dữ liệu BloodHound JSON AD
                    com.fasterxml.jackson.databind.JsonNode bhNode = rootNode.path("recon").path("bloodhoundAudit");
                    if (bhNode.isMissingNode() || bhNode.isNull()) {
                        bhNode = rootNode.path("bloodhoundAudit");
                    }
                    if (!bhNode.isMissingNode() && !bhNode.isNull()) {
                        try {
                            BloodhoundAuditSummaryDto bhSummary = mapper.treeToValue(bhNode, BloodhoundAuditSummaryDto.class);
                            if (bhSummary != null && bhSummary.getTotalObjectsScanned() > 0) {
                                for (BloodhoundFindingDto bf : bhSummary.getHighRiskFindings()) {
                                    Severity sev = "CRITICAL".equalsIgnoreCase(bf.getRiskLevel()) ? Severity.CRITICAL
                                            : "HIGH".equalsIgnoreCase(bf.getRiskLevel()) ? Severity.HIGH : Severity.MEDIUM;
                                    findings.add(VulnerabilityFinding.builder()
                                            .title("Rủi ro quyền AD: " + bf.getRelationshipType() + " -> " + bf.getTargetObject())
                                            .severity(sev)
                                            .target(bf.getTargetObject())
                                            .serviceName("Active Directory (BloodHound)")
                                            .description(bf.getDescription())
                                            .evidence("Source: " + bf.getSourcePrincipal() + " | Edge: " + bf.getRelationshipType() + " | Target: " + bf.getTargetObject())
                                            .exploitationVector("Kẻ tấn công có thể lạm dụng quyền " + bf.getRelationshipType() + " để kiểm soát hoặc nâng đặc quyền trên tài nguyên này.")
                                            .remediation(bf.getRemediation())
                                            .createdAt(LocalDateTime.now())
                                            .build());
                                }
                                scanSummaryBuilder.append(bloodhoundFilterService.buildCompactPromptSummary(bhSummary));
                            }
                        } catch (Exception ex) {
                            log.warn("Không thể map bloodhoundAudit node: {}", ex.getMessage());
                        }
                    } else if (rootNode.has("data") || (rootNode.has("meta") && rootNode.path("meta").has("methods"))) {
                        BloodhoundAuditSummaryDto bhSummary = bloodhoundFilterService.filterAndSummarize(task.getParsedSummary());
                        if (bhSummary != null && bhSummary.getTotalObjectsScanned() > 0) {
                            for (BloodhoundFindingDto bf : bhSummary.getHighRiskFindings()) {
                                Severity sev = "CRITICAL".equalsIgnoreCase(bf.getRiskLevel()) ? Severity.CRITICAL
                                        : "HIGH".equalsIgnoreCase(bf.getRiskLevel()) ? Severity.HIGH : Severity.MEDIUM;
                                findings.add(VulnerabilityFinding.builder()
                                        .title("Rủi ro quyền AD: " + bf.getRelationshipType() + " -> " + bf.getTargetObject())
                                        .severity(sev)
                                        .target(bf.getTargetObject())
                                        .serviceName("Active Directory (BloodHound)")
                                        .description(bf.getDescription())
                                        .evidence("Source: " + bf.getSourcePrincipal() + " | Edge: " + bf.getRelationshipType() + " | Target: " + bf.getTargetObject())
                                        .exploitationVector("Kẻ tấn công có thể lạm dụng quyền " + bf.getRelationshipType() + " để kiểm soát hoặc nâng đặc quyền trên tài nguyên này.")
                                        .remediation(bf.getRemediation())
                                        .createdAt(LocalDateTime.now())
                                        .build());
                            }
                            scanSummaryBuilder.append(bloodhoundFilterService.buildCompactPromptSummary(bhSummary));
                        }
                    }

                    com.fasterxml.jackson.databind.JsonNode reconNode = rootNode.path("recon");
                    if (!reconNode.isMissingNode() && !reconNode.isNull()) {
                        com.fasterxml.jackson.databind.JsonNode vulnsNode = reconNode.path("vulnerabilityAudit").path("findings");
                        if (vulnsNode.isArray()) {
                            for (com.fasterxml.jackson.databind.JsonNode v : vulnsNode) {
                                String sevStr = v.path("severity").asText("MEDIUM");
                                Severity sev = Severity.MEDIUM;
                                try { sev = Severity.valueOf(sevStr); } catch (Exception ignored) {}
                                String exploitVec = v.path("exploitationVector").asText("");
                                if (exploitVec.isBlank()) {
                                    exploitVec = "Kẻ tấn công có thể lợi dụng điểm yếu này để tiếp cận dữ liệu hoặc mở rộng bề mặt tấn công.";
                                }
                                String titleVal = v.path("title").asText("Lỗ hổng cấu hình");
                                String cveIdVal = !v.path("cveId").isMissingNode() && !v.path("cveId").isNull() ? v.path("cveId").asText() : (!v.path("id").asText("").startsWith("VULN-") ? v.path("id").asText(null) : null);
                                boolean alreadyExists = findings.stream().anyMatch(f ->
                                        (cveIdVal != null && f.getCveId() != null && f.getCveId().equalsIgnoreCase(cveIdVal)) ||
                                        (f.getTitle() != null && f.getTitle().equalsIgnoreCase(titleVal)));
                                if (!alreadyExists) {
                                    findings.add(VulnerabilityFinding.builder()
                                            .title(titleVal)
                                            .severity(sev)
                                            .target(task.getTarget())
                                            .serviceName(v.path("category").asText("Config Audit"))
                                            .cveId(cveIdVal)
                                            .exploitAvailable(v.path("exploitAvailable").asBoolean(false))
                                            .cisaKev(v.path("cisaKev").asBoolean(false))
                                            .exploitMaturity(v.path("exploitMaturity").asText(null))
                                            .impact(v.path("impact").asText(null))
                                            .referenceUrl(v.path("references").asText(null))
                                            .description(v.path("description").asText(""))
                                            .evidence(v.path("evidence").asText(""))
                                            .exploitationVector(exploitVec)
                                            .remediation(v.path("remediation").asText("Cập nhật cấu hình bảo mật."))
                                            .createdAt(LocalDateTime.now())
                                            .build());
                                }
                            }
                        }

                        scanSummaryBuilder.append("\n=== RECONNAISSANCE & THÔNG TIN BẢO MẬT TỔNG HỢP ===\n");
                        scanSummaryBuilder.append("Mục tiêu: ").append(task.getTarget()).append("\n");
                        if (reconNode.has("executiveSummary")) {
                            scanSummaryBuilder.append("Tóm tắt: ").append(reconNode.path("executiveSummary").asText()).append("\n");
                        }
                    }
                } catch (Exception ignored) {}
            }
        }

        if (findings.isEmpty()) {
            findings.add(VulnerabilityFinding.builder()
                    .title("Không phát hiện lỗ hổng mức độ nghiêm trọng trên các cổng cơ bản")
                    .severity(Severity.INFO)
                    .target(assessment.getName())
                    .serviceName("Network Discovery")
                    .description("Các cổng dịch vụ thông dụng đều được đóng hoặc lọc qua Firewall.")
                    .evidence("Nmap scan logs: All common filtered or clean.")
                    .exploitationVector("Không phát hiện vector tấn công khả thi từ các cổng dịch vụ cơ bản đã quét.")
                    .remediation("Tiếp tục duy trì chính sách bảo mật định kỳ.")
                    .createdAt(LocalDateTime.now())
                    .build());
        }


        LlmAnalysisResult llmAnalysis = llmService.analyzeFindings(
                assessment.getName(),
                scanSummaryBuilder.toString()
        );

        int critical = (int) findings.stream().filter(f -> f.getSeverity() == Severity.CRITICAL).count();
        int high = (int) findings.stream().filter(f -> f.getSeverity() == Severity.HIGH).count();
        int medium = (int) findings.stream().filter(f -> f.getSeverity() == Severity.MEDIUM).count();
        int low = (int) findings.stream().filter(f -> f.getSeverity() == Severity.LOW).count();
        int info = (int) findings.stream().filter(f -> f.getSeverity() == Severity.INFO).count();

        Severity overallRisk = critical > 0 ? Severity.CRITICAL
                : high > 0 ? Severity.HIGH
                : medium > 0 ? Severity.MEDIUM
                : low > 0 ? Severity.LOW : Severity.INFO;

        String title = request != null && request.title() != null && !request.title().isEmpty()
                ? request.title()
                : "Báo Cáo Đánh Giá An Toàn Thông Tin: " + assessment.getName();

        String author = request != null && request.generatedBy() != null
                ? request.generatedBy()
                : "Hệ thống Quản trị ATTT Portal";

        AssessmentReport report = AssessmentReport.builder()
                .assessmentId(assessmentId)
                .title(title)
                .executiveSummary(llmAnalysis.executiveSummary())
                .overallRisk(overallRisk)
                .totalFindings(findings.size())
                .criticalCount(critical)
                .highCount(high)
                .mediumCount(medium)
                .lowCount(low)
                .infoCount(info)
                .recommendations(String.join("\n- ", llmAnalysis.recommendations()))
                .generatedBy(author)
                .generatedAt(LocalDateTime.now())
                .build();

        for (VulnerabilityFinding finding : findings) {
            finding.setReport(report);
            if (finding.getMitreTechniqueId() == null || finding.getMitreTechniqueId().isBlank()) {
                mitreMappingService.mapFinding(finding);
            }
            report.getFindings().add(finding);
        }

        AssessmentReport savedReport = reportRepository.save(report);

        assessment.setStatus(AssessmentStatus.COMPLETED);
        assessmentRepository.save(assessment);

        auditLogService.log(
                author,
                "GENERATE_REPORT",
                "reporting",
                assessment.getName(),
                "ReportID=" + savedReport.getId() + ", Findings=" + findings.size() + ", Risk=" + overallRisk,
                AuditDecision.ALLOWED,
                "SUCCESS",
                null,
                null
        );

        return toDto(savedReport);
    }

    @Override
    @Transactional(readOnly = true)
    public String exportReportAsMarkdown(Long reportId) {
        AssessmentReport report = reportRepository.findById(reportId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy báo cáo ID: " + reportId));

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        StringBuilder md = new StringBuilder();

        md.append("# ").append(report.getTitle()).append("\n\n");
        md.append("**Người tạo:** ").append(report.getGeneratedBy()).append(" | ");
        md.append("**Thời gian:** ").append(report.getGeneratedAt().format(dtf)).append(" | ");
        md.append("**Mức độ rủi ro tổng thể:** `").append(report.getOverallRisk()).append("`\n\n");

        md.append("## 1. Tóm Tắt Dành Cho Lãnh Đạo (Executive Summary)\n\n");
        md.append(report.getExecutiveSummary() != null ? report.getExecutiveSummary() : "Không có tóm tắt.").append("\n\n");

        md.append("## 2. Thống Kê Điểm Yếu An Toàn\n\n");
        md.append("| Mức độ | Số lượng |\n");
        md.append("|:---|:---|\n");
        md.append("| 🔴 **CRITICAL** | ").append(report.getCriticalCount()).append(" |\n");
        md.append("| 🟠 **HIGH** | ").append(report.getHighCount()).append(" |\n");
        md.append("| 🟡 **MEDIUM** | ").append(report.getMediumCount()).append(" |\n");
        md.append("| 🔵 **LOW** | ").append(report.getLowCount()).append(" |\n");
        md.append("| ⚪ **INFO** | ").append(report.getInfoCount()).append(" |\n\n");

        md.append("## 3. Chi Tiết Các Phát Hiện Lỗ Hổng & Hướng Khai Thác\n\n");
        int count = 1;
        for (VulnerabilityFinding f : report.getFindings()) {
            md.append("### 3.").append(count++).append(". [").append(f.getSeverity()).append("] ").append(f.getTitle()).append("\n\n");
            md.append("- **Mục tiêu:** `").append(f.getTarget()).append("`");
            if (f.getPort() != null) md.append(" (Port: `").append(f.getPort()).append("`)");
            if (f.getCveId() != null) md.append(" | **CVE ID:** `").append(f.getCveId()).append("`");
            md.append("\n");
            if (Boolean.TRUE.equals(f.getCisaKev())) {
                md.append("- **🔥 CISA KEV Status:** `KNOWN_EXPLOITED_IN_THE_WILD` (Lỗ hổng đang bị hacker khai thác tích cực ngoài thực tế)\n");
            } else if (Boolean.TRUE.equals(f.getExploitAvailable())) {
                md.append("- **⚡ Trạng thái mã khai thác:** `PUBLIC_POC_AVAILABLE` (Đã có mã khai thác/PoC công khai trên Exploit-DB/GitHub)\n");
            }
            if (f.getImpact() != null && !f.getImpact().isBlank()) {
                md.append("- **⚠️ Hậu quả khi bị khai thác:** ").append(f.getImpact()).append("\n");
            }
            if (f.getMitreTechniqueId() != null && !f.getMitreTechniqueId().isBlank()) {
                md.append("- **🛡️ MITRE ATT&CK:** `").append(f.getMitreTechniqueId())
                  .append(" (").append(f.getMitreTechniqueName() != null ? f.getMitreTechniqueName() : "").append(")`")
                  .append(" | Chiến thuật: `").append(f.getMitreTactic() != null ? f.getMitreTactic() : "").append("`\n");
            }
            if (f.getDescription() != null) md.append("- **Mô tả:** ").append(f.getDescription()).append("\n");
            if (f.getEvidence() != null) md.append("- **Bằng chứng kỹ thuật:** `").append(f.getEvidence()).append("`\n");
            if (f.getExploitationVector() != null && !f.getExploitationVector().isBlank()) {
                md.append("- **🎯 Cơ chế Hacker hoạt động (Attack Vector):** ").append(f.getExploitationVector()).append("\n");
            }
            if (f.getRemediation() != null) md.append("- **Khuyến nghị khắc phục:** ").append(f.getRemediation()).append("\n");
            if (f.getReferenceUrl() != null && !f.getReferenceUrl().isBlank()) {
                md.append("- **Tra cứu chi tiết:** [NVD NIST] (").append(f.getReferenceUrl()).append(")\n");
            }
            md.append("\n");
        }

        md.append("## 4. Kiến Nghị & Khắc Phục Chung\n\n");
        md.append(report.getRecommendations() != null ? report.getRecommendations() : "Duy trì tuân thủ chính sách bảo mật.").append("\n");

        return md.toString();
    }

    private void evaluatePortRisk(String hostIp, PortResult port, List<VulnerabilityFinding> findings) {
        if ("open".equalsIgnoreCase(port.state())) {
            List<com.example.backend.modules.recon.VulnerabilityFindingDto> cves = new ArrayList<>();
            if (port.scripts() != null && !port.scripts().isEmpty()) {
                cves.addAll(cveIntelligenceService.extractCvesFromNmapScripts(hostIp, port.portId(), port.scripts()));
            }
            if (port.version() != null && !port.version().isBlank()) {
                cves.addAll(cveIntelligenceService.lookupCvesForServiceVersion(hostIp, port.portId(), port.serviceName(), port.product(), port.version()));
            }
            
            for (com.example.backend.modules.recon.VulnerabilityFindingDto cve : cves) {
                boolean alreadyExists = findings.stream().anyMatch(f ->
                        (f.getCveId() != null && f.getCveId().equals(cve.getCveId())) ||
                        (f.getTitle() != null && f.getTitle().equals(cve.getTitle())));
                
                if (!alreadyExists) {
                    Severity sev = Severity.MEDIUM;
                    try {
                        if (cve.getSeverity() != null) sev = Severity.valueOf(cve.getSeverity().toUpperCase());
                    } catch (Exception ignored) {}

                    findings.add(VulnerabilityFinding.builder()
                            .title(cve.getTitle())
                            .severity(sev)
                            .target(hostIp)
                            .serviceName(port.serviceName() != null ? port.serviceName() : cve.getCategory())
                            .port(port.portId())
                            .cveId(cve.getCveId())
                            .exploitAvailable(cve.getExploitAvailable())
                            .cisaKev(cve.getCisaKev())
                            .exploitMaturity(cve.getExploitMaturity())
                            .impact(cve.getImpact())
                            .referenceUrl(cve.getReferences())
                            .description(cve.getDescription())
                            .evidence(cve.getEvidence() != null ? cve.getEvidence() : "Port " + port.portId() + "/tcp open " + port.serviceName())
                            .exploitationVector(cve.getExploitationVector())
                            .remediation(cve.getRemediation())
                            .createdAt(LocalDateTime.now())
                            .build());
                }
            }

            // Giữ lại các đánh giá cấu hình cơ bản nếu chưa có CVE cụ thể
            if (port.portId() == 80 && findings.stream().noneMatch(f -> f.getPort() != null && f.getPort() == 80)) {
                findings.add(VulnerabilityFinding.builder()
                        .title("Dịch vụ Web HTTP chạy không mã hóa (Clear-text Transport)")
                        .severity(Severity.MEDIUM)
                        .target(hostIp)
                        .serviceName("HTTP / " + port.product())
                        .port(80)
                        .description("Phát hiện Web Server mở cổng 80 mà không bắt buộc chuyển hướng HTTPS, tạo nguy cơ bị nghe lén dữ liệu.")
                        .evidence("Port 80/tcp open http " + port.product() + " " + port.version())
                        .exploitationVector("Kẻ tấn công trên cùng mạng nội bộ hoặc Wi-Fi công cộng thực hiện tấn công Man-in-the-Middle (ARP Spoofing / Packet Sniffing) để bắt gói tin và đọc trộm mật khẩu/dữ liệu truyền dạng không mã hóa.")
                        .remediation("Cấu hình chứng chỉ SSL/TLS và thiết lập tự động chuyển hướng HTTP -> HTTPS.")
                        .createdAt(LocalDateTime.now())
                        .build());
            }
        }
    }

    @Override
    @Transactional(readOnly = true)
    public AssessmentReportDto getReportByAssessmentId(Long assessmentId) {
        return reportRepository.findTopByAssessmentIdOrderByGeneratedAtDesc(assessmentId)
                .map(this::toDto)
                .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public AssessmentReportDto getReportById(Long id) {
        AssessmentReport report = reportRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy báo cáo ID: " + id));
        return toDto(report);
    }

    private AssessmentReportDto toDto(AssessmentReport report) {
        List<FindingDto> findingDtos = report.getFindings().stream()
                .map(f -> new FindingDto(
                        f.getId(),
                        f.getTitle(),
                        f.getSeverity(),
                        f.getTarget(),
                        f.getServiceName(),
                        f.getPort(),
                        f.getCveId(),
                        f.getDescription(),
                        f.getEvidence(),
                        f.getExploitationVector(),
                        f.getRemediation(),
                        f.getExploitAvailable(),
                        f.getCisaKev(),
                        f.getExploitMaturity(),
                        f.getImpact(),
                        f.getReferenceUrl(),
                        f.getMitreTactic(),
                        f.getMitreTechniqueId(),
                        f.getMitreTechniqueName(),
                        f.getCreatedAt()
                ))
                .toList();


        return new AssessmentReportDto(
                report.getId(),
                report.getAssessmentId(),
                report.getTitle(),
                report.getExecutiveSummary(),
                report.getOverallRisk(),
                report.getTotalFindings(),
                report.getCriticalCount(),
                report.getHighCount(),
                report.getMediumCount(),
                report.getLowCount(),
                report.getInfoCount(),
                report.getRecommendations(),
                report.getGeneratedBy(),
                findingDtos,
                report.getGeneratedAt()
        );
    }
}
