package com.example.backend.modules.recon;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class ReconServiceImpl implements ReconService {

    private final DnsReconService dnsReconService;
    private final WhoisService whoisService;
    private final HttpSecurityScannerService httpSecurityScannerService;
    private final WebDirectoryScannerService webDirectoryScannerService;
    private final TechStackDetectionService techStackDetectionService;
    private final VulnerabilityAuditService vulnerabilityAuditService;
    private final BloodhoundFilterService bloodhoundFilterService;
    private final BloodhoundAdCollectorService bloodhoundAdCollectorService;

    @Override
    public DnsReconResult performDnsRecon(String target) {
        return dnsReconService.performDnsRecon(target);
    }

    @Override
    public WhoisResult performWhois(String target) {
        return whoisService.queryWhois(target);
    }

    @Override
    public HttpSecurityScanResult scanHttpSecurity(String target) {
        return httpSecurityScannerService.scanHttpSecurity(target);
    }

    @Override
    public WebDirectoryScanResult scanWebDirectories(String target) {
        return webDirectoryScannerService.scanDirectories(target);
    }

    @Override
    public TechStackScanResult detectTechStack(String target) {
        return techStackDetectionService.detectTechStack(target);
    }

    @Override
    public VulnerabilityAuditResult auditVulnerabilities(String target) {
        return vulnerabilityAuditService.auditTarget(target);
    }

    @Override
    public ComprehensiveReconResult performComprehensiveRecon(String target) {
        long startTime = System.currentTimeMillis();
        log.info("Bắt đầu Comprehensive Reconnaissance & Vulnerability Audit cho mục tiêu: {}", target);
        java.util.concurrent.CompletableFuture<DnsReconResult> dnsFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return dnsReconService.performDnsRecon(target);
                    } catch (Exception e) {
                        return null;
                    }
                });
        java.util.concurrent.CompletableFuture<WhoisResult> whoisFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return whoisService.queryWhois(target);
                    } catch (Exception e) {
                        return null;
                    }
                });
        java.util.concurrent.CompletableFuture<HttpSecurityScanResult> httpSecFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return httpSecurityScannerService.scanHttpSecurity(target);
                    } catch (Exception e) {
                        return null;
                    }
                });
        java.util.concurrent.CompletableFuture<WebDirectoryScanResult> webDirsFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return webDirectoryScannerService.scanDirectories(target);
                    } catch (Exception e) {
                        return null;
                    }
                });
        java.util.concurrent.CompletableFuture<TechStackScanResult> techStackFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return techStackDetectionService.detectTechStack(target);
                    } catch (Exception e) {
                        return null;
                    }
                });
        java.util.concurrent.CompletableFuture<VulnerabilityAuditResult> vulnAuditFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return vulnerabilityAuditService.auditTarget(target);
                    } catch (Exception e) {
                        return null;
                    }
                });
        java.util.concurrent.CompletableFuture<BloodhoundAuditSummaryDto> bloodhoundFuture = java.util.concurrent.CompletableFuture
                .supplyAsync(() -> {
                    try {
                        return autoScanBloodhoundIfAdDetected(target);
                    } catch (Exception e) {
                        return null;
                    }
                });

        try {
            java.util.concurrent.CompletableFuture
                    .allOf(dnsFuture, whoisFuture, httpSecFuture, webDirsFuture, techStackFuture, vulnAuditFuture, bloodhoundFuture)
                    .get(20, java.util.concurrent.TimeUnit.SECONDS);
        } catch (Exception e) {
            log.warn("Comprehensive recon tổng thể kết thúc sớm hoặc timeout: {}", e.getMessage());
        }

        DnsReconResult dns = dnsFuture.getNow(null);
        WhoisResult whois = whoisFuture.getNow(null);
        HttpSecurityScanResult httpSec = httpSecFuture.getNow(null);
        WebDirectoryScanResult webDirs = webDirsFuture.getNow(null);
        TechStackScanResult techStack = techStackFuture.getNow(null);
        VulnerabilityAuditResult vulnAudit = vulnAuditFuture.getNow(null);
        BloodhoundAuditSummaryDto bloodhoundAudit = bloodhoundFuture.getNow(null);

        // Tự động chuyển đổi các phát hiện BloodHound ACLs thành lỗ hổng để ném trực tiếp cho AI phân tích
        if (bloodhoundAudit != null && vulnAudit != null && bloodhoundAudit.getHighRiskFindings() != null) {
            for (BloodhoundFindingDto bf : bloodhoundAudit.getHighRiskFindings()) {
                VulnerabilityFindingDto vf = VulnerabilityFindingDto.builder()
                        .id("AD-BLOODHOUND-" + bf.getRelationshipType().toUpperCase())
                        .title(String.format("Lỗ hổng phân quyền Active Directory: %s (%s)", bf.getRelationshipType(), bf.getSourcePrincipal()))
                        .severity(bf.getRiskLevel() != null ? bf.getRiskLevel().toUpperCase() : "HIGH")
                        .category("ACTIVE_DIRECTORY_BLOODHOUND")
                        .cvssScore("CRITICAL".equalsIgnoreCase(bf.getRiskLevel()) ? 9.2 : 7.8)
                        .description(bf.getDescription())
                        .evidence(String.format("Quan hệ quyền: %s ➔ [%s] ➔ %s (Target Type: %s)", bf.getSourcePrincipal(), bf.getRelationshipType(), bf.getTargetObject(), bf.getTargetType()))
                        .exploitationVector(String.format("Khai thác leo thang đặc quyền Domain Admin thông qua quyền %s từ tài khoản %s lên đối tượng %s bằng lệnh Windows CMD / PowerShell native (net user, nltest, klist, ADSI Searcher).", bf.getRelationshipType(), bf.getSourcePrincipal(), bf.getTargetObject()))
                        .remediation(bf.getRemediation())
                        .build();
                vulnAudit.getFindings().add(vf);
                if ("CRITICAL".equalsIgnoreCase(bf.getRiskLevel())) {
                    vulnAudit.setCriticalCount(vulnAudit.getCriticalCount() + 1);
                } else {
                    vulnAudit.setHighCount(vulnAudit.getHighCount() + 1);
                }
            }
        }

        long totalDuration = System.currentTimeMillis() - startTime;

        // Xây dựng Pentest Tree / Attack Surface Tree
        AttackSurfaceTreeDto attackTree = buildAttackSurfaceTree(target, dns, techStack, vulnAudit, webDirs, httpSec);

        // Sinh executive summary
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("Báo cáo bề mặt tấn công cho mục tiêu: %s. ", target));
        if (dns != null && dns.isSuccess()) {
            sb.append(
                    String.format("DNS: %d IP(s), %d bản ghi. ", dns.getResolvedIps().size(), dns.getRecords().size()));
        }
        if (techStack != null && techStack.isSuccess()) {
            sb.append(
                    String.format("Công nghệ: Nhận diện %d frameworks/services. ", techStack.getTechnologies().size()));
        }
        if (vulnAudit != null && vulnAudit.isSuccess()) {
            sb.append(String.format("Lỗ hổng cấu hình: %d điểm yếu (%d High/Critical). ",
                    vulnAudit.getFindings().size(), vulnAudit.getCriticalCount() + vulnAudit.getHighCount()));
        }
        if (bloodhoundAudit != null && bloodhoundAudit.getTotalObjectsScanned() > 0) {
            sb.append(String.format("BloodHound AD: Phân tích %d đối tượng (Phát hiện %d chuỗi quyền nguy hiểm). ",
                    bloodhoundAudit.getTotalObjectsScanned(), bloodhoundAudit.getHighRiskFindings().size()));
        }
        if (httpSec != null && httpSec.isSuccess()) {
            sb.append(String.format("HTTP Security: Đạt điểm %d/100 (Hạng %s). ", httpSec.getScore(),
                    httpSec.getGrade()));
        }
        if (webDirs != null && webDirs.isSuccess()) {
            sb.append(String.format("Web Paths: Phát hiện %d đường dẫn (có %d đường dẫn nhạy cảm).",
                    webDirs.getDiscoveredPaths().size(), webDirs.getSensitiveCount()));
        }

        return ComprehensiveReconResult.builder()
                .target(target)
                .scannedAt(LocalDateTime.now())
                .dns(dns)
                .whois(whois)
                .httpSecurity(httpSec)
                .webDirectories(webDirs)
                .techStack(techStack)
                .vulnerabilityAudit(vulnAudit)
                .bloodhoundAudit(bloodhoundAudit)
                .attackTree(attackTree)
                .executiveSummary(sb.toString())
                .totalDurationMs(totalDuration)
                .build();
    }


    private AttackSurfaceTreeDto buildAttackSurfaceTree(
            String target,
            DnsReconResult dns,
            TechStackScanResult techStack,
            VulnerabilityAuditResult vulnAudit,
            WebDirectoryScanResult webDirs,
            HttpSecurityScanResult httpSec) {
        List<AttackSurfaceTreeDto> rootChildren = new ArrayList<>();

        // 1. Nhánh Network & Endpoints
        List<AttackSurfaceTreeDto> networkNodes = new ArrayList<>();
        if (dns != null && dns.getResolvedIps() != null) {
            for (String ip : dns.getResolvedIps()) {
                networkNodes.add(AttackSurfaceTreeDto.builder()
                        .id("ip-" + ip)
                        .label(ip)
                        .type("NETWORK_IP")
                        .status("ONLINE")
                        .details("Địa chỉ IP máy chủ phân giải")
                        .build());
            }
        }
        rootChildren.add(AttackSurfaceTreeDto.builder()
                .id("tree-network")
                .label("Tầng Mạng & Địa chỉ IP (" + networkNodes.size() + ")")
                .type("CATEGORY")
                .status("ONLINE")
                .details("Các điểm cuối IP phân giải từ tên miền")
                .children(networkNodes)
                .build());

        // 2. Nhánh Tech Stack
        List<AttackSurfaceTreeDto> techNodes = new ArrayList<>();
        if (techStack != null && techStack.getTechnologies() != null) {
            for (TechStackItemDto t : techStack.getTechnologies()) {
                techNodes.add(AttackSurfaceTreeDto.builder()
                        .id("tech-" + t.getName())
                        .label(t.getName() + " [" + t.getCategory() + "]")
                        .type("TECH_STACK")
                        .status("INFO")
                        .details(t.getEvidence())
                        .build());
            }
        }
        rootChildren.add(AttackSurfaceTreeDto.builder()
                .id("tree-tech")
                .label("Công nghệ & Nền tảng (" + techNodes.size() + ")")
                .type("CATEGORY")
                .status("INFO")
                .details("Các Frameworks, Web Server, CMS đã nhận diện")
                .children(techNodes)
                .build());

        // 3. Nhánh Vulnerabilities & Misconfigurations
        List<AttackSurfaceTreeDto> vulnNodes = new ArrayList<>();
        if (vulnAudit != null && vulnAudit.getFindings() != null) {
            for (VulnerabilityFindingDto v : vulnAudit.getFindings()) {
                vulnNodes.add(AttackSurfaceTreeDto.builder()
                        .id("vuln-" + v.getId())
                        .label("[" + v.getSeverity() + "] " + v.getTitle())
                        .type("VULNERABILITY")
                        .status(v.getSeverity().equals("CRITICAL") || v.getSeverity().equals("HIGH") ? "VULNERABLE"
                                : "WARNING")
                        .details(v.getDescription())
                        .build());
            }
        }
        rootChildren.add(AttackSurfaceTreeDto.builder()
                .id("tree-vulns")
                .label("Lỗ hổng & Điểm yếu Cấu hình (" + vulnNodes.size() + ")")
                .type("CATEGORY")
                .status(vulnNodes.isEmpty() ? "SECURE" : "VULNERABLE")
                .details("Kết quả kiểm thử tự động các điểm yếu cấu hình")
                .children(vulnNodes)
                .build());

        // 4. Nhánh Exposed Paths
        List<AttackSurfaceTreeDto> pathNodes = new ArrayList<>();
        if (webDirs != null && webDirs.getDiscoveredPaths() != null) {
            for (WebDirResultDto p : webDirs.getDiscoveredPaths()) {
                pathNodes.add(AttackSurfaceTreeDto.builder()
                        .id("path-" + p.getPath())
                        .label(p.getPath() + " (" + p.getStatusText() + ")")
                        .type("DIRECTORY")
                        .status(p.isSensitive() ? "WARNING" : "INFO")
                        .details("URL: " + p.getUrl())
                        .build());
            }
        }
        rootChildren.add(AttackSurfaceTreeDto.builder()
                .id("tree-paths")
                .label("Đường dẫn & Tệp tin Phát hiện (" + pathNodes.size() + ")")
                .type("CATEGORY")
                .status("INFO")
                .details("Danh sách đường dẫn phản hồi HTTP hợp lệ")
                .children(pathNodes)
                .build());

        return AttackSurfaceTreeDto.builder()
                .id("root-target")
                .label("Mục Tiêu: " + target)
                .type("ROOT")
                .status("ONLINE")
                .details("Cây bề mặt tấn công phân cấp tổng hợp")
                .children(rootChildren)
                .build();
    }

    /**
     * Tự động phát hiện cổng dịch vụ Active Directory / LDAP (389, 636) trên mục tiêu.
     * Nếu mục tiêu là Domain Controller hoặc mở cổng LDAP, tự động thu thập đồ thị quyền BloodHound thực tế 100%.
     */
    private BloodhoundAuditSummaryDto autoScanBloodhoundIfAdDetected(String target) {
        String host = extractCleanHost(target);
        int port = extractPortOrDefault(target, 389);
        // Kiểm tra xem cổng LDAP 389 hoặc 636 có mở trên mục tiêu không
        boolean isLdapOpen = isPortOpen(host, port, 1200) || isPortOpen(host, 636, 1200);
        if (isLdapOpen) {
            try {
                log.info("[AUTO_BLOODHOUND] Phát hiện cổng LDAP ({}:{}) mở trên mục tiêu {}. Bắt đầu tự động quét BloodHound...", host, port, target);
                String domain = (host.contains(".") && !host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) ? host : "";
                if (domain.isBlank()) {
                    log.info("[AUTO_BLOODHOUND] Cổng LDAP ({}:{}) mở nhưng mục tiêu là IP ({}) chưa có tên miền (Domain) và tài khoản xác thực, vui lòng dùng tab Kiểm Thử AD để quét chi tiết.", host, port, host);
                    return null;
                }
                String json = bloodhoundAdCollectorService.collectDomainData(AdScanRequestDto.builder()
                        .host(host)
                        .port(port)
                        .domain(domain)
                        .method("LDAP")
                        .build());
                return bloodhoundFilterService.filterAndSummarize(json);
            } catch (Exception ex) {
                log.info("[AUTO_BLOODHOUND] Mục tiêu mở cổng LDAP ({}:{}) nhưng cần xác thực danh tính để trích xuất đầy đủ: {}", host, port, ex.getMessage());
            }
        }
        return null;
    }

    private boolean isPortOpen(String host, int port, int timeoutMs) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private String extractCleanHost(String target) {
        if (target == null) return "127.0.0.1";
        String t = target.trim();
        if (t.contains("://")) {
            t = t.substring(t.indexOf("://") + 3);
        }
        int slashIdx = t.indexOf('/');
        if (slashIdx != -1) t = t.substring(0, slashIdx);
        int colonIdx = t.indexOf(':');
        if (colonIdx != -1) t = t.substring(0, colonIdx);
        return t.trim();
    }

    private int extractPortOrDefault(String target, int defaultPort) {
        if (target == null) return defaultPort;
        String t = target.trim();
        if (t.contains("://")) {
            t = t.substring(t.indexOf("://") + 3);
        }
        int slashIdx = t.indexOf('/');
        if (slashIdx != -1) t = t.substring(0, slashIdx);
        int colonIdx = t.indexOf(':');
        if (colonIdx != -1) {
            try {
                return Integer.parseInt(t.substring(colonIdx + 1));
            } catch (Exception ignored) {}
        }
        return defaultPort;
    }
}