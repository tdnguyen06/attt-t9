package com.example.backend.modules.scan;

import com.example.backend.modules.audit.AuditDecision;
import com.example.backend.modules.audit.AuditLogService;
import com.example.backend.modules.planning.PlanStep;
import com.example.backend.modules.planning.StepStatus;
import com.example.backend.modules.planning.PlanStepRepository;
import com.example.backend.modules.scope.ScopeCheckResult;
import com.example.backend.modules.scope.ScopeService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScanServiceImpl implements ScanService {

    private final ScanTaskRepository scanTaskRepository;
    private final PlanStepRepository planStepRepository;
    private final ScopeService scopeService;
    private final NmapXmlParser nmapXmlParser;
    private final AuditLogService auditLogService;
    private final com.example.backend.modules.recon.ReconService reconService;
    private final com.example.backend.modules.assessment.AssessmentRepository assessmentRepository;
    private final com.example.backend.modules.planning.AssessmentPlanRepository planRepository;
    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .findAndRegisterModules()
            .registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule());

    private final org.springframework.context.ApplicationContext applicationContext;

    private final ExecutorService executorService = Executors.newFixedThreadPool(4);

    @Override
    @Transactional
    public ScanTask createScanTask(CreateScanTaskRequest request) {
        log.info("Creating Nmap scan task for target: {} with profile: {}", request.target(), request.profile());

        ScopeCheckResult scopeCheck = scopeService.verifyTargetInScope(request.assessmentId(), request.target());
        if (!scopeCheck.inScope()) {
            auditLogService.log("operator", "CREATE_SCAN_TASK", "scan", request.target(),
                    "Profile=" + request.profile(), AuditDecision.DENIED, "OUT_OF_SCOPE", scopeCheck.message(), null);
            throw new IllegalArgumentException("Không thể tạo tác vụ quét: " + scopeCheck.message());
        }

        String safeCommand = buildSafeNmapCommand(request.profile(), request.target());

        ScanTask task = ScanTask.builder()
                .assessmentId(request.assessmentId())
                .target(request.target().trim())
                .profile(request.profile())
                .commandLine(safeCommand)
                .status(ScanStatus.PENDING)
                .createdAt(LocalDateTime.now())
                .build();

        ScanTask saved = scanTaskRepository.save(task);

        auditLogService.log("operator", "CREATE_SCAN_TASK", "scan", request.target(),
                "TaskID=" + saved.getId() + ", Profile=" + request.profile() + ", Command=" + safeCommand,
                AuditDecision.ALLOWED, "QUEUED", null, null);

        return saved;
    }

    @Override
    @Transactional
    public ScanTask runScanForPlanStep(PlanStep step) {
        Long assessmentId = step.getPlan().getAssessmentId();
        ScanProfile profile;
        try {
            profile = ScanProfile.valueOf(step.getProfile().toUpperCase());
        } catch (Exception e) {
            profile = ScanProfile.QUICK_SCAN;
        }

        String safeCommand = buildSafeNmapCommand(profile, step.getTarget());

        ScanTask task = ScanTask.builder()
                .assessmentId(assessmentId)
                .stepId(step.getId())
                .target(step.getTarget())
                .profile(profile)
                .commandLine(safeCommand)
                .status(ScanStatus.RUNNING)
                .startedAt(LocalDateTime.now())
                .createdAt(LocalDateTime.now())
                .build();

        ScanTask savedTask = scanTaskRepository.save(task);

        step.setScanTaskId(savedTask.getId());
        step.setStatus(StepStatus.RUNNING);
        planStepRepository.save(step);

        dispatchScanExecution(savedTask.getId(), step.getId(), safeCommand, profile, step.getTarget(), 180);

        return savedTask;
    }

    @Override
    public void dispatchScanExecution(Long scanTaskId, Long stepId, String command, ScanProfile profile, String target, int timeoutSeconds) {
        executorService.submit(() -> {
            long startTime = System.currentTimeMillis();
            log.info("[SCAN_ENGINE] Bắt đầu quét TaskID={} với lệnh: '{}' và đồng thời chạy Recon toàn diện", scanTaskId, command);

            try {
                // Chạy song song Nmap scan và Comprehensive Recon (DNS, WHOIS, HTTP Headers/SSL, Web Dirs)
                java.util.concurrent.CompletableFuture<String> nmapFuture = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try {
                        return executeNmapCommand(command, timeoutSeconds, profile, target);
                    } catch (Exception e) {
                        log.error("[SCAN_ENGINE] Nmap scan failed for target {}: {}", target, e.getMessage());
                        return null;
                    }
                }, executorService);

                java.util.concurrent.CompletableFuture<com.example.backend.modules.recon.ComprehensiveReconResult> reconFuture = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                    try {
                        return reconService.performComprehensiveRecon(target);
                    } catch (Exception e) {
                        log.error("[SCAN_ENGINE] Recon failed for target {}: {}", target, e.getMessage());
                        return null;
                    }
                }, executorService);

                String xmlOutput = null;
                try {
                    xmlOutput = nmapFuture.get(timeoutSeconds + 5, TimeUnit.SECONDS);
                } catch (Exception e) {
                    log.warn("[SCAN_ENGINE] Nmap task timeout hoặc lỗi: {}", e.getMessage());
                }

                com.example.backend.modules.recon.ComprehensiveReconResult reconResult = null;
                try {
                    reconResult = reconFuture.get(35, TimeUnit.SECONDS);
                } catch (Exception e) {
                    log.warn("[SCAN_ENGINE] Recon task timeout hoặc lỗi: {}", e.getMessage());
                }

                long duration = System.currentTimeMillis() - startTime;

                ScanTask completedTask = completeScanWithXmlAndRecon(scanTaskId, xmlOutput, reconResult);

                scanTaskRepository.findById(scanTaskId).ifPresent(t -> {
                    t.setDurationMs(duration);
                    t.setExitCode(0);
                    scanTaskRepository.save(t);
                });

                if (stepId != null) {
                    final com.example.backend.modules.recon.ComprehensiveReconResult finalRecon = reconResult;
                    planStepRepository.findById(stepId).ifPresent(s -> {
                        s.setStatus(StepStatus.SUCCESS);
                        String summary = "Hoàn thành quét toàn diện (" + String.format("%.1f", duration / 1000.0) + "s)";
                        try {
                            if (completedTask.getParsedSummary() != null) {
                                com.fasterxml.jackson.databind.JsonNode rootNode = objectMapper.readTree(completedTask.getParsedSummary());
                                int openPorts = rootNode.path("totalOpenPorts").asInt(0);
                                int hostsUp = rootNode.path("totalHostsUp").asInt(1);
                                String extraInfo = "";
                                if (finalRecon != null && finalRecon.getHttpSecurity() != null && finalRecon.getHttpSecurity().isSuccess()) {
                                    extraInfo = ", HTTP Grade: " + finalRecon.getHttpSecurity().getGrade();
                                }
                                summary = "Thành công (" + String.format("%.1f", duration / 1000.0) + "s): " + openPorts + " cổng mở, Host " + (hostsUp > 0 ? "ONLINE" : "OFFLINE") + extraInfo;
                            }
                        } catch (Exception ignored) {}
                        s.setResultSummary(summary);
                        planStepRepository.save(s);
                    });
                }

                checkAndUpdateAssessmentProgress(stepId, scanTaskId);
            } catch (Exception e) {
                long duration = System.currentTimeMillis() - startTime;
                log.error("[SCAN_ENGINE] TaskID={} thất bại: {}", scanTaskId, e.getMessage());
                handleScanError(scanTaskId, stepId, duration, 1, e.getMessage());
                checkAndUpdateAssessmentProgress(stepId, scanTaskId);
            }
        });
    }

    private void checkAndUpdateAssessmentProgress(Long stepId, Long scanTaskId) {
        try {
            Long assessmentId = null;
            if (stepId != null) {
                PlanStep step = planStepRepository.findById(stepId).orElse(null);
                if (step != null) {
                    Long planId = step.getPlan() != null ? step.getPlan().getId() : null;
                    if (planId != null) {
                        com.example.backend.modules.planning.AssessmentPlan plan = planRepository.findById(planId).orElse(null);
                        if (plan != null) {
                            List<PlanStep> steps = planStepRepository.findByPlanIdOrderByStepNumberAsc(planId);
                            boolean allFinished = steps.stream()
                                    .allMatch(s -> s.getStatus() == StepStatus.SUCCESS || s.getStatus() == StepStatus.FAILED || s.getStatus() == StepStatus.REJECTED);
                            if (allFinished) {
                                plan.setStatus(com.example.backend.modules.planning.PlanStatus.COMPLETED);
                                planRepository.save(plan);
                            }
                            assessmentId = plan.getAssessmentId();
                        }
                    }
                }
            } else if (scanTaskId != null) {
                ScanTask task = scanTaskRepository.findById(scanTaskId).orElse(null);
                if (task != null) {
                    assessmentId = task.getAssessmentId();
                }
            }

            if (assessmentId != null) {
                assessmentRepository.findById(assessmentId).ifPresent(a -> {
                    List<ScanTask> tasks = scanTaskRepository.findByAssessmentIdOrderByCreatedAtDesc(a.getId());
                    boolean allTasksDone = tasks.stream().allMatch(t -> t.getStatus() == ScanStatus.COMPLETED || t.getStatus() == ScanStatus.FAILED);
                    if (allTasksDone && !tasks.isEmpty()) {
                        a.setStatus(com.example.backend.modules.assessment.AssessmentStatus.COMPLETED);
                        a.setUpdatedAt(LocalDateTime.now());
                        assessmentRepository.save(a);
                        log.info("[ASSESSMENT_ENGINE] Assessment ID={} đã hoàn tất toàn bộ tiến trình quét -> COMPLETED", a.getId());

                        // Tự động phân tích AI và tổng hợp báo cáo lưu vào DB ngay sau khi quét xong
                        Long targetAssessmentId = a.getId();
                        String assessmentName = a.getName();
                        executorService.submit(() -> {
                            try {
                                com.example.backend.modules.reporting.AssessmentReportRepository reportRepo =
                                        applicationContext.getBean(com.example.backend.modules.reporting.AssessmentReportRepository.class);
                                if (reportRepo.findTopByAssessmentIdOrderByGeneratedAtDesc(targetAssessmentId).isEmpty()) {
                                    log.info("[ASSESSMENT_ENGINE] Tự động kích hoạt AI phân tích & tổng hợp báo cáo cho Assessment ID={}", targetAssessmentId);
                                    com.example.backend.modules.reporting.ReportingService reportingService =
                                            applicationContext.getBean(com.example.backend.modules.reporting.ReportingService.class);
                                    reportingService.generateReport(targetAssessmentId,
                                            new com.example.backend.modules.reporting.GenerateReportRequest("Báo Cáo Đánh Giá An Toàn: " + assessmentName, "Hệ Thống Tự Động AI"));
                                }
                            } catch (Exception ex) {
                                log.warn("[ASSESSMENT_ENGINE] Không thể tự động tạo báo cáo AI sau khi quét: {}", ex.getMessage());
                            }
                        });
                    }
                });
            }
        } catch (Exception e) {
            log.error("Lỗi khi cập nhật trạng thái Assessment sau khi quét: {}", e.getMessage());
        }
    }

    private void handleScanError(Long scanTaskId, Long stepId, long duration, int exitCode, String errorMsg) {
        scanTaskRepository.findById(scanTaskId).ifPresent(t -> {
            t.setStatus(ScanStatus.FAILED);
            t.setErrorMessage(errorMsg);
            t.setDurationMs(duration);
            t.setExitCode(exitCode);
            t.setCompletedAt(LocalDateTime.now());
            scanTaskRepository.save(t);
        });

        if (stepId != null) {
            planStepRepository.findById(stepId).ifPresent(s -> {
                s.setStatus(StepStatus.FAILED);
                s.setResultSummary("Thất bại: " + errorMsg);
                planStepRepository.save(s);
            });
        }
    }

    private String getNmapExecutablePath() {
        try {
            Process p = new ProcessBuilder("nmap", "-V").start();
            if (p.waitFor(2, TimeUnit.SECONDS) && p.exitValue() == 0) {
                return "nmap";
            }
        } catch (Exception ignored) {}

        List<String> commonPaths = List.of(
                "C:\\Program Files (x86)\\Nmap\\nmap.exe",
                "C:\\Program Files\\Nmap\\nmap.exe",
                "C:\\Nmap\\nmap.exe"
        );
        for (String path : commonPaths) {
            java.io.File file = new java.io.File(path);
            if (file.exists() && file.isFile()) {
                return path;
            }
        }

        return null;
    }

    private String fallbackSocketScan(String target) {
        String host = extractHost(target);
        log.info("[SCAN_ENGINE] Chạy chế độ dò quét Socket TCP dự phòng cho mục tiêu: {}", host);
        int[] commonPorts = {21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 464, 587, 593, 636, 1433, 1521, 3268, 3269, 3306, 3389, 5432, 5985, 8080, 8443};
        java.util.Map<Integer, String> serviceMap = java.util.Map.ofEntries(
                java.util.Map.entry(21, "ftp"),
                java.util.Map.entry(22, "ssh"),
                java.util.Map.entry(23, "telnet"),
                java.util.Map.entry(25, "smtp"),
                java.util.Map.entry(53, "domain"),
                java.util.Map.entry(80, "http"),
                java.util.Map.entry(88, "kerberos-sec"),
                java.util.Map.entry(110, "pop3"),
                java.util.Map.entry(135, "msrpc"),
                java.util.Map.entry(139, "netbios-ssn"),
                java.util.Map.entry(143, "imap"),
                java.util.Map.entry(389, "ldap"),
                java.util.Map.entry(443, "https"),
                java.util.Map.entry(445, "microsoft-ds"),
                java.util.Map.entry(464, "kpasswd5"),
                java.util.Map.entry(587, "submission"),
                java.util.Map.entry(593, "ncacn_http"),
                java.util.Map.entry(636, "ldapssl"),
                java.util.Map.entry(1433, "ms-sql-s"),
                java.util.Map.entry(1521, "oracle"),
                java.util.Map.entry(3268, "globalcatLDAP"),
                java.util.Map.entry(3269, "globalcatLDAPssl"),
                java.util.Map.entry(3306, "mysql"),
                java.util.Map.entry(3389, "ms-wbt-server"),
                java.util.Map.entry(5432, "postgresql"),
                java.util.Map.entry(5985, "http"),
                java.util.Map.entry(8080, "http-proxy"),
                java.util.Map.entry(8443, "https-alt")
        );

        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<nmaprun scanner=\"socket-scanner\" args=\"socket-probe ").append(host).append("\" version=\"1.0\">\n");
        xml.append("<host><status state=\"up\"/>\n");
        xml.append("<address addr=\"").append(host).append("\" addrtype=\"ipv4\"/>\n");
        xml.append("<ports>\n");

        int openCount = 0;
        for (int p : commonPorts) {
            try (java.net.Socket s = new java.net.Socket()) {
                s.connect(new java.net.InetSocketAddress(host, p), 350);
                openCount++;
                String svc = serviceMap.getOrDefault(p, "unknown");
                xml.append("<port protocol=\"tcp\" portid=\"").append(p).append("\">");
                xml.append("<state state=\"open\"/>");
                xml.append("<service name=\"").append(svc).append("\"/>");
                xml.append("</port>\n");
            } catch (Exception ignored) {}
        }
        xml.append("</ports></host>\n");
        xml.append("<runstats><hosts up=\"1\" down=\"0\" total=\"1\"/></runstats>\n");
        xml.append("</nmaprun>");

        log.info("[SCAN_ENGINE] Hoàn thành quét socket dự phòng: tìm thấy {} cổng mở trên {}", openCount, host);
        return xml.toString();
    }

    private String executeNmapCommand(String command, int timeoutSeconds, ScanProfile profile, String target) throws Exception {
        String nmapPath = getNmapExecutablePath();
        if (nmapPath == null) {
            log.warn("[SCAN_ENGINE] Không tìm thấy nmap.exe trên hệ thống, tự động kích hoạt Socket Scanner fallback");
            return fallbackSocketScan(target);
        }

        String host = extractHost(target);
        String port = extractPort(target);
        List<String> cmdArgs = new java.util.ArrayList<>();
        cmdArgs.add(nmapPath);
        boolean hasScanType = false;
        boolean hasPortArg = false;
        for (String arg : profile.getSafeArguments().split("\\s+")) {
            if (!arg.trim().isEmpty()) {
                if (arg.equals("-sT") || arg.equals("-sS") || arg.equals("-sU") || arg.equals("-sV")) {
                    if (arg.equals("-sT") || arg.equals("-sS")) hasScanType = true;
                }
                if (arg.startsWith("-p")) {
                    hasPortArg = true;
                }
                cmdArgs.add(arg.trim());
            }
        }
        if (!hasScanType) {
            cmdArgs.add(1, "-sT");
        }
        if (port != null && !hasPortArg) {
            cmdArgs.add("-p");
            cmdArgs.add(port);
        }
        cmdArgs.add("-oX");
        cmdArgs.add("-");
        cmdArgs.add(host);

        log.info("[SCAN_ENGINE] Chạy lệnh Nmap thật: {}", String.join(" ", cmdArgs));

        try {
            ProcessBuilder pb = new ProcessBuilder(cmdArgs);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Đọc stdout song song để tránh deadlock tràn bộ đệm I/O của Windows
            java.util.concurrent.CompletableFuture<String> readOutputFuture = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\n");
                    }
                    return output.toString();
                } catch (Exception e) {
                    return "";
                }
            });

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                readOutputFuture.cancel(true);
                log.warn("[SCAN_ENGINE] Lệnh Nmap bị timeout sau {}s, chuyển sang Socket Scanner fallback", timeoutSeconds);
                return fallbackSocketScan(target);
            }

            String result;
            try {
                result = readOutputFuture.get(5, TimeUnit.SECONDS);
            } catch (Exception e) {
                result = "";
            }

            if (result == null || !result.contains("<nmaprun")) {
                log.warn("[SCAN_ENGINE] Nmap không trả về XML hợp lệ, chuyển sang Socket Scanner fallback");
                return fallbackSocketScan(target);
            }

            return result;
        } catch (Exception e) {
            log.error("[SCAN_ENGINE] Lỗi khi thực thi Nmap: {}. Kích hoạt Socket Scanner fallback", e.getMessage());
            return fallbackSocketScan(target);
        }
    }

    private String extractHost(String target) {
        if (target == null) return "127.0.0.1";
        String t = target.trim();
        if (t.contains("://")) {
            try {
                URI uri = URI.create(t);
                if (uri.getHost() != null) {
                    return uri.getHost();
                }
            } catch (Exception ignored) {}
            t = t.substring(t.indexOf("://") + 3);
        }
        int slashIdx = t.indexOf('/');
        if (slashIdx != -1) {
            t = t.substring(0, slashIdx);
        }
        int colonIdx = t.indexOf(':');
        if (colonIdx != -1) {
            t = t.substring(0, colonIdx);
        }
        return t.trim();
    }

    private String extractPort(String target) {
        if (target == null) return null;
        String t = target.trim();
        if (t.contains("://")) {
            try {
                URI uri = URI.create(t);
                if (uri.getPort() > 0) {
                    return String.valueOf(uri.getPort());
                }
            } catch (Exception ignored) {}
            t = t.substring(t.indexOf("://") + 3);
        }
        int slashIdx = t.indexOf('/');
        if (slashIdx != -1) {
            t = t.substring(0, slashIdx);
        }
        int colonIdx = t.indexOf(':');
        if (colonIdx != -1) {
            String portStr = t.substring(colonIdx + 1);
            if (portStr.matches("\\d+")) {
                return portStr;
            }
        }
        return null;
    }

    @Transactional
    public ScanTask completeScanWithXmlAndRecon(Long taskId, String xmlOutput, com.example.backend.modules.recon.ComprehensiveReconResult reconResult) {
        ScanTask task = scanTaskRepository.findById(taskId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy Scan Task ID: " + taskId));

        task.setRawXmlOutput(xmlOutput);
        task.setCompletedAt(LocalDateTime.now());

        try {
            java.util.Map<String, Object> summaryMap = new java.util.HashMap<>();
            int hostsUp = 1;
            int openPorts = 0;

            if (xmlOutput != null && !xmlOutput.isBlank() && xmlOutput.contains("<nmaprun")) {
                NmapScanResult parsedResult = nmapXmlParser.parse(xmlOutput);
                hostsUp = parsedResult.totalHostsUp();
                openPorts = parsedResult.totalOpenPorts();
                summaryMap.put("totalHostsUp", hostsUp);
                summaryMap.put("totalOpenPorts", openPorts);
                summaryMap.put("hosts", parsedResult.hosts());
                summaryMap.put("scanner", parsedResult.scanner());
                summaryMap.put("scanTime", parsedResult.scanTime());

                // Tra cứu CVE thực tế cho toàn bộ cổng/dịch vụ quét được
                try {
                    com.example.backend.modules.recon.CveIntelligenceService cveIntelligenceService =
                            applicationContext.getBean(com.example.backend.modules.recon.CveIntelligenceService.class);
                    if (reconResult == null) {
                        reconResult = new com.example.backend.modules.recon.ComprehensiveReconResult();
                    }
                    if (reconResult.getVulnerabilityAudit() == null) {
                        reconResult.setVulnerabilityAudit(new com.example.backend.modules.recon.VulnerabilityAuditResult());
                    }
                    List<com.example.backend.modules.recon.VulnerabilityFindingDto> existingFindings =
                            reconResult.getVulnerabilityAudit().getFindings();
                    if (existingFindings == null) {
                        existingFindings = new java.util.ArrayList<>();
                        reconResult.getVulnerabilityAudit().setFindings(existingFindings);
                    }

                    for (HostResult h : parsedResult.hosts()) {
                        String hostIp = h.ipAddress() != null ? h.ipAddress() : task.getTarget();
                        for (PortResult p : h.ports()) {
                            if ("open".equalsIgnoreCase(p.state())) {
                                // 1. Trích xuất các lỗ hổng CVE thật được Nmap NSE Scripts phát hiện
                                if (p.scripts() != null && !p.scripts().isEmpty()) {
                                    List<com.example.backend.modules.recon.VulnerabilityFindingDto> scriptCves =
                                            cveIntelligenceService.extractCvesFromNmapScripts(hostIp, p.portId(), p.scripts());
                                    for (com.example.backend.modules.recon.VulnerabilityFindingDto cve : scriptCves) {
                                        boolean alreadyExists = existingFindings.stream()
                                                .anyMatch(f -> f.getId() != null && f.getId().equals(cve.getId()));
                                        if (!alreadyExists) {
                                            existingFindings.add(cve);
                                        }
                                    }
                                }

                                // 2. Tra cứu CVE thực tế dựa trên phiên bản dịch vụ phát hiện được
                                if (p.version() != null && !p.version().isBlank()) {
                                    List<com.example.backend.modules.recon.VulnerabilityFindingDto> versionCves =
                                            cveIntelligenceService.lookupCvesForServiceVersion(hostIp, p.portId(), p.serviceName(), p.product(), p.version());
                                    for (com.example.backend.modules.recon.VulnerabilityFindingDto cve : versionCves) {
                                        boolean alreadyExists = existingFindings.stream()
                                                .anyMatch(f -> f.getId() != null && f.getId().equals(cve.getId()));
                                        if (!alreadyExists) {
                                            existingFindings.add(cve);
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Cập nhật lại số lượng rủi ro
                    int crit = 0, high = 0, med = 0, low = 0, info = 0;
                    for (com.example.backend.modules.recon.VulnerabilityFindingDto f : existingFindings) {
                        switch (f.getSeverity()) {
                            case "CRITICAL" -> crit++;
                            case "HIGH" -> high++;
                            case "MEDIUM" -> med++;
                            case "LOW" -> low++;
                            default -> info++;
                        }
                    }
                    reconResult.getVulnerabilityAudit().setCriticalCount(crit);
                    reconResult.getVulnerabilityAudit().setHighCount(high);
                    reconResult.getVulnerabilityAudit().setMediumCount(med);
                    reconResult.getVulnerabilityAudit().setLowCount(low);
                    reconResult.getVulnerabilityAudit().setInfoCount(info);
                    reconResult.getVulnerabilityAudit().setSummary(
                            String.format("Phát hiện %d lỗ hổng bảo mật & CVE thực tế (%d Critical, %d High, %d Medium, %d Low).",
                                    existingFindings.size(), crit, high, med, low));
                    reconResult.getVulnerabilityAudit().setSuccess(true);
                } catch (Exception cveEx) {
                    log.warn("[SCAN_ENGINE] Lỗi khi tra cứu CVE cho các cổng quét: {}", cveEx.getMessage());
                }
            } else {
                summaryMap.put("totalHostsUp", 1);
                summaryMap.put("totalOpenPorts", 0);
                summaryMap.put("hosts", java.util.List.of());
            }

            if (reconResult != null) {
                summaryMap.put("recon", reconResult);
            }

            // Tự động phân tích & giải thích kết quả quét bằng AI (All-In-One Scan & AI)
            try {
                com.example.backend.modules.llm.LlmService llmService = applicationContext.getBean(com.example.backend.modules.llm.LlmService.class);
                String initialSummaryJson = objectMapper.writeValueAsString(summaryMap);
                com.example.backend.modules.llm.LlmScanExplanation explanation = llmService.explainScanResult(
                        taskId,
                        task.getTarget(),
                        task.getProfile() != null ? task.getProfile().name() : "FULL_COMPREHENSIVE_SCAN",
                        initialSummaryJson,
                        xmlOutput
                );
                if (explanation != null) {
                    String explanationJson = objectMapper.writeValueAsString(explanation);
                    task.setAiExplanation(explanationJson);
                    summaryMap.put("aiExplanation", explanation);
                }
            } catch (Exception aiEx) {
                log.warn("[SCAN_ENGINE] Không thể tự động phân tích AI cho TaskID={}: {}", taskId, aiEx.getMessage());
            }

            String summaryJson = objectMapper.writeValueAsString(summaryMap);
            task.setParsedSummary(summaryJson);
            task.setStatus(ScanStatus.COMPLETED);

            auditLogService.log("system", "COMPLETE_SCAN", "scan", task.getTarget(),
                    "TaskID=" + taskId + ", HostsUp=" + hostsUp + ", OpenPorts=" + openPorts + ", HasRecon=" + (reconResult != null) + ", HasAiExplanation=" + (task.getAiExplanation() != null),
                    AuditDecision.EXECUTED, "SUCCESS", null, null);
        } catch (Exception e) {
            log.error("Lỗi khi tổng hợp kết quả quét & recon: {}", e.getMessage());
            task.setStatus(ScanStatus.FAILED);
            task.setErrorMessage("Lỗi tổng hợp kết quả: " + e.getMessage());

            auditLogService.log("system", "COMPLETE_SCAN", "scan", task.getTarget(),
                    "TaskID=" + taskId, AuditDecision.FAILED, "PARSER_ERROR", e.getMessage(), null);
        }

        return scanTaskRepository.save(task);
    }

    @Override
    @Transactional
    public ScanTask completeScanWithXml(Long taskId, String xmlOutput) {
        return completeScanWithXmlAndRecon(taskId, xmlOutput, null);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ScanTask> getTasksByAssessmentId(Long assessmentId) {
        return scanTaskRepository.findByAssessmentIdOrderByCreatedAtDesc(assessmentId);
    }

    @Override
    @Transactional(readOnly = true)
    public ScanTask getTaskById(Long taskId) {
        return scanTaskRepository.findById(taskId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy Scan Task ID: " + taskId));
    }

    @Override
    public String buildSafeNmapCommand(ScanProfile profile, String target) {
        String host = extractHost(target);
        String port = extractPort(target);
        if (port != null && !profile.getSafeArguments().contains("-p")) {
            return String.format("nmap %s -p %s -oX - %s", profile.getSafeArguments(), port, host);
        }
        return String.format("nmap %s -oX - %s", profile.getSafeArguments(), host);
    }
}
