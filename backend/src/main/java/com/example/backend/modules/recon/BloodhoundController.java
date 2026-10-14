package com.example.backend.modules.recon;
 
import com.example.backend.modules.assessment.AssessmentRepository;
import com.example.backend.modules.llm.LlmService;
import com.example.backend.modules.scan.ScanProfile;
import com.example.backend.modules.scan.ScanStatus;
import com.example.backend.modules.scan.ScanTask;
import com.example.backend.modules.scan.ScanTaskRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping({"/api/bloodhound", "/api/ad", "/api/active-directory", "/bloodhound"})
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
@Slf4j
public class BloodhoundController {

    private final BloodhoundFilterService bloodhoundFilterService;
    private final BloodhoundAdCollectorService bloodhoundAdCollectorService;
    private final LlmService llmService;
    private final ScanTaskRepository scanTaskRepository;
    private final AssessmentRepository assessmentRepository;
    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .findAndRegisterModules();

    public BloodhoundAuditSummaryDto processUnifiedBloodhoundAnalysis(String rawJson, String domain, String host, String authUser) {
        log.info("Executing Unified BloodHound Analysis via AI (domain: {}, host: {}, user: {})", domain, host, authUser);
        BloodhoundAuditSummaryDto summary = bloodhoundFilterService.filterAndSummarize(rawJson, authUser);
        if (domain != null && !domain.isBlank() && (summary.getDomainName() == null || summary.getDomainName().isBlank())) {
            summary.setDomainName(domain);
        }
        if (authUser != null && !authUser.isBlank()) {
            summary.setAuthenticatedUser(authUser);
            summary.setHasValidCredentials(true);
        }

        // Gửi TOÀN BỘ dữ liệu đồ thị BloodHound cho AI phân tích sâu sát trong cùng 1 bước duy nhất
        String aiPrompt = bloodhoundFilterService.buildComprehensiveAiPrompt(rawJson, summary, summary.getDomainName(), host, authUser);
        try {
            var chatRes = llmService.chatWithAssistant(
                    aiPrompt,
                    "BẠN LÀ CHUYÊN GIA BẢO MẬT ACTIVE DIRECTORY CẤP CAO. Hãy phân tích toàn bộ dữ liệu đồ thị BloodHound, nhận diện chính xác từng đối tượng (User/Computer Account như WIN-...$/GPO/Domain), giải thích rõ các quyền hạn ACLs, và đưa ra chuỗi tấn công leo quyền (Kill Chain) cùng các bước khai thác lỗ hổng chi tiết."
            );
            if (chatRes != null && chatRes.reply() != null) {
                summary.setAiAnalysis(chatRes.reply());
            }
        } catch (Exception ex) {
            log.warn("Lỗi khi AI phân tích BloodHound: {}", ex.getMessage());
            summary.setAiAnalysis("### ⚠️ Đang kết nối dịch vụ AI\n\n" +
                    "- **Chi tiết:** " + (ex.getMessage() != null ? ex.getMessage() : "Dịch vụ AI đang phản hồi chậm hoặc chưa sẵn sàng") + "\n" +
                    "- Hệ thống đã hoàn tất bóc tách danh sách lỗ hổng và quan hệ phân quyền ở bảng bên dưới.");
        }
        return summary;
    }

    @PostMapping(value = "/analyze", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_PLAIN_VALUE})
    public ResponseEntity<BloodhoundAuditSummaryDto> analyzeBloodhoundJson(@RequestBody String rawJson) {
        log.info("Received BloodHound JSON analysis request (size: {} bytes)", rawJson != null ? rawJson.length() : 0);
        return ResponseEntity.ok(processUnifiedBloodhoundAnalysis(rawJson, null, null, null));
    }

    @PostMapping(value = "/ai-analyze", consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_PLAIN_VALUE})
    public ResponseEntity<BloodhoundAuditSummaryDto> aiAnalyzeBloodhoundJson(@RequestBody String rawJson) {
        log.info("Received BloodHound AI analysis request (size: {} bytes)", rawJson != null ? rawJson.length() : 0);
        return ResponseEntity.ok(processUnifiedBloodhoundAnalysis(rawJson, null, null, null));
    }

    @GetMapping("/history")
    public ResponseEntity<java.util.List<Map<String, Object>>> getBloodhoundScanHistory() {
        var tasks = scanTaskRepository.findAllByOrderByCreatedAtDesc();
        java.util.List<Map<String, Object>> result = new java.util.ArrayList<>();
        for (var t : tasks) {
            if (t.getParsedSummary() != null && (t.getParsedSummary().contains("bloodhoundAudit") || t.getParsedSummary().contains("highRiskFindings"))) {
                try {
                    com.fasterxml.jackson.databind.JsonNode root = objectMapper.readTree(t.getParsedSummary());
                    com.fasterxml.jackson.databind.JsonNode bh = root.path("recon").path("bloodhoundAudit");
                    if (bh.isMissingNode() || bh.isNull()) {
                        bh = root.path("bloodhoundAudit");
                    }
                    if (!bh.isMissingNode() && !bh.isNull()) {
                        BloodhoundAuditSummaryDto summaryDto = null;
                        try {
                            summaryDto = objectMapper.treeToValue(bh, BloodhoundAuditSummaryDto.class);
                        } catch (Exception ex) {
                            log.warn("Không thể map JsonNode sang BloodhoundAuditSummaryDto: {}", ex.getMessage());
                        }

                        Map<String, Object> item = new HashMap<>();
                        item.put("taskId", t.getId());
                        item.put("assessmentId", t.getAssessmentId());
                        item.put("target", t.getTarget());
                        item.put("status", t.getStatus() != null ? t.getStatus().name() : "COMPLETED");
                        item.put("createdAt", t.getCreatedAt());

                        String authUser = "";
                        if (summaryDto != null && summaryDto.getAuthenticatedUser() != null && !summaryDto.getAuthenticatedUser().isBlank()) {
                            authUser = summaryDto.getAuthenticatedUser();
                        } else {
                            JsonNode authNode = root.path("recon").path("authenticatedUser");
                            if (!authNode.isMissingNode() && !authNode.asText().isBlank()) {
                                authUser = authNode.asText();
                            }
                        }

                        boolean hasCreds = !authUser.isBlank();
                        if (summaryDto != null) {
                            summaryDto.setAuthenticatedUser(hasCreds ? authUser : null);
                            summaryDto.setHasValidCredentials(hasCreds);
                            item.put("summary", summaryDto);
                            item.put("domain", summaryDto.getDomainName());
                            item.put("totalObjects", summaryDto.getTotalObjectsScanned());
                            item.put("highRiskCount", summaryDto.getCriticalRiskCount() + summaryDto.getHighRiskCount());
                        } else {
                            Map<String, Object> fallbackMap = objectMapper.treeToValue(bh, Map.class);
                            fallbackMap.put("authenticatedUser", hasCreds ? authUser : null);
                            fallbackMap.put("hasValidCredentials", hasCreds);
                            item.put("summary", fallbackMap);
                            item.put("domain", fallbackMap.get("domainName"));
                            item.put("totalObjects", fallbackMap.get("totalObjectsScanned"));
                        }

                        item.put("authenticatedUser", authUser);
                        item.put("hasValidCredentials", hasCreds);
                        item.put("aiExplanation", t.getAiExplanation());
                        result.add(item);
                    }
                } catch (Exception ignored) {}
            }
        }
        return ResponseEntity.ok(result);
    }

    @DeleteMapping("/history/{taskId}")
    public ResponseEntity<?> deleteBloodhoundHistoryItem(@PathVariable Long taskId) {
        log.info("Deleting BloodHound ScanTask history for ID: {}", taskId);
        try {
            var taskOpt = scanTaskRepository.findById(taskId);
            if (taskOpt.isPresent()) {
                scanTaskRepository.delete(taskOpt.get());
                return ResponseEntity.ok(Map.of("message", "Đã xóa lịch sử quét Task #" + taskId + " thành công.", "taskId", taskId));
            }
            return ResponseEntity.notFound().build();
        } catch (Exception e) {
            log.error("Lỗi khi xóa lịch sử quét Task {}: {}", taskId, e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Lỗi khi xóa: " + e.getMessage()));
        }
    }

    @DeleteMapping("/history/all")
    public ResponseEntity<?> deleteAllBloodhoundHistory() {
        log.info("Deleting ALL BloodHound history tasks...");
        try {
            var tasks = scanTaskRepository.findAll();
            int count = 0;
            for (var t : tasks) {
                if (t.getParsedSummary() != null && (t.getParsedSummary().contains("bloodhoundAudit") || t.getParsedSummary().contains("highRiskFindings"))) {
                    scanTaskRepository.delete(t);
                    count++;
                }
            }
            return ResponseEntity.ok(Map.of("message", "Đã xóa toàn bộ " + count + " lần quét Active Directory cũ.", "deletedCount", count));
        } catch (Exception e) {
            log.error("Lỗi khi xóa toàn bộ lịch sử BloodHound: {}", e.getMessage());
            return ResponseEntity.status(500).body(Map.of("error", "Lỗi khi xóa: " + e.getMessage()));
        }
    }

    @PostMapping(value = "/attach-to-task/{taskId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<com.example.backend.modules.scan.ScanTask> attachBloodhoundToTask(
            @PathVariable Long taskId,
            @RequestParam("file") MultipartFile file) {
        try {
            log.info("Attaching BloodHound file to Task ID: {}", taskId);
            String rawJson = new String(file.getBytes(), StandardCharsets.UTF_8);
            BloodhoundAuditSummaryDto summary = processUnifiedBloodhoundAnalysis(rawJson, null, null, null);

            com.example.backend.modules.scan.ScanTask task = scanTaskRepository.findById(taskId)
                    .orElseThrow(() -> new IllegalArgumentException("Task không tồn tại: " + taskId));

            Map<String, Object> summaryMap = new HashMap<>();
            if (task.getParsedSummary() != null && !task.getParsedSummary().isBlank()) {
                try {
                    summaryMap = objectMapper.readValue(task.getParsedSummary(), Map.class);
                } catch (Exception ignored) {}
            }
            Map<String, Object> reconMap = (Map<String, Object>) summaryMap.getOrDefault("recon", new HashMap<>());
            reconMap.put("bloodhoundAudit", summary);
            summaryMap.put("recon", reconMap);

            // Tự động phân tích AI kết hợp toàn diện (quét mạng + cấu hình AD)
            try {
                String updatedSummaryJson = objectMapper.writeValueAsString(summaryMap);
                var explanation = llmService.explainScanResult(
                        taskId,
                        task.getTarget(),
                        task.getProfile() != null ? task.getProfile().name() : "FULL_COMPREHENSIVE_SCAN",
                        updatedSummaryJson,
                        task.getRawXmlOutput()
                );
                if (explanation != null) {
                    task.setAiExplanation(objectMapper.writeValueAsString(explanation));
                    summaryMap.put("aiExplanation", explanation);
                }
            } catch (Exception ex) {
                log.warn("Lỗi khi LLM giải thích sau khi attach BloodHound: {}", ex.getMessage());
            }

            task.setParsedSummary(objectMapper.writeValueAsString(summaryMap));
            com.example.backend.modules.scan.ScanTask saved = scanTaskRepository.save(task);
            return ResponseEntity.ok(saved);
        } catch (Exception e) {
            log.error("Lỗi khi đính kèm BloodHound vào Task {}: {}", taskId, e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<BloodhoundAuditSummaryDto> uploadBloodhoundFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "includeAi", defaultValue = "true") boolean includeAi) {
        try {
            log.info("Uploaded BloodHound file: {} (size: {} bytes)", file.getOriginalFilename(), file.getSize());
            String rawJson = new String(file.getBytes(), StandardCharsets.UTF_8);
            BloodhoundAuditSummaryDto summary = processUnifiedBloodhoundAnalysis(rawJson, null, null, null);
            return ResponseEntity.ok(summary);
        } catch (Exception e) {
            log.error("Failed to parse uploaded BloodHound file: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }


    @PostMapping("/scan-environment")
    public ResponseEntity<?> scanAdEnvironment(@RequestBody(required = false) AdScanRequestDto request) {
        if (request == null) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Vui lòng nhập đầy đủ thông tin kết nối Active Directory (Domain, Host, Username, Password).",
                    "status", "FAILED"
            ));
        }

        String domain = request.getDomain() != null ? request.getDomain().trim() : "";
        if (domain.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Tên miền Active Directory (Domain) không được để trống.",
                    "status", "FAILED"
            ));
        }

        String method = request.getMethod() != null ? request.getMethod().trim().toUpperCase() : "LDAP";
        if (request.getHost() == null || request.getHost().isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Địa chỉ máy chủ Domain Controller (Host / IP) không được để trống.",
                    "status", "FAILED"
            ));
        }
            if (request.getUsername() == null || request.getUsername().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Tài khoản xác thực Active Directory (Username) không được để trống. BloodHound yêu cầu tài khoản miền để truy vấn cây đối tượng và ACLs (Active Directory từ chối Anonymous Bind).",
                        "status", "FAILED"
                ));
            }
            if (request.getPassword() == null || request.getPassword().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error", "Mật khẩu tài khoản Active Directory (Password) không được để trống.",
                        "status", "FAILED"
                ));
            }

        log.info("Executing Live BloodHound AD Collector scan [Method: {}, Domain: {}, Host: {}, User: {}]",
                method, domain, request.getHost(), request.getUsername());

        String jsonContent;
        try {
            jsonContent = bloodhoundAdCollectorService.collectDomainData(request);
            log.info("Thu thập thành công dữ liệu Active Directory thực tế từ domain {}", domain);
        } catch (Exception ex) {
            log.warn("Lỗi khi thu thập từ AD: {}", ex.getMessage());
            String errorMsg = ex.getMessage();
            if (errorMsg != null && errorMsg.contains("data 52e")) {
                errorMsg = "Sai tên đăng nhập hoặc mật khẩu Active Directory (Lỗi Windows: data 52e). Vui lòng kiểm tra lại tài khoản và mật khẩu.";
            } else if (errorMsg != null && errorMsg.contains("data 525")) {
                errorMsg = "Tài khoản không tồn tại trên hệ thống Active Directory (Lỗi Windows: data 525).";
            } else if (errorMsg != null && errorMsg.contains("data 775")) {
                errorMsg = "Tài khoản Active Directory đã bị khóa do nhập sai mật khẩu nhiều lần (Lỗi Windows: data 775).";
            }
            return ResponseEntity.badRequest().body(Map.of(
                    "error", errorMsg != null ? errorMsg : "Không thể thu thập dữ liệu từ Active Directory",
                    "status", "FAILED"
            ));
        }

        String finalAuthUser = (request.getUsername() != null && !request.getUsername().isBlank())
                ? request.getUsername().trim()
                : "";

        // Tự động phân tích toàn diện đồ thị AD và tạo báo cáo AI trong cùng 1 bước duy nhất
        BloodhoundAuditSummaryDto summary = processUnifiedBloodhoundAnalysis(jsonContent, domain, request.getHost(), finalAuthUser);

        // Lưu kết quả quét vào Database (ScanTask) để người dùng có lịch sử quét thật và mới nhất
        Long targetAssessmentId = request.getAssessmentId();
        if (targetAssessmentId == null) {
            var allAssessments = assessmentRepository.findAllByOrderByCreatedAtDesc();
            targetAssessmentId = allAssessments.stream()
                    .filter(a -> a.getName() != null && (
                            a.getName().toLowerCase().contains("active directory") ||
                            a.getName().toLowerCase().contains(" ad") ||
                            a.getName().toLowerCase().contains("miền")
                    ))
                    .map(com.example.backend.modules.assessment.Assessment::getId)
                    .findFirst()
                    .orElseGet(() -> allAssessments.stream()
                            .filter(a -> a.getId().equals(1L))
                            .map(com.example.backend.modules.assessment.Assessment::getId)
                            .findFirst()
                            .orElse(1L));
        }

        Map<String, Object> summaryMap = new HashMap<>();
        Map<String, Object> reconMap = new HashMap<>();
        reconMap.put("bloodhoundAudit", summary);
        reconMap.put("authenticatedUser", finalAuthUser);
        reconMap.put("hasValidCredentials", true);
        summaryMap.put("recon", reconMap);
        if (summary.getAiAnalysis() != null) {
            summaryMap.put("aiExplanation", summary.getAiAnalysis());
        }

        String summaryJson = "";
        try {
            summaryJson = objectMapper.writeValueAsString(summaryMap);
        } catch (Exception ignored) {}

        com.example.backend.modules.scan.ScanTask newTask = com.example.backend.modules.scan.ScanTask.builder()
                .assessmentId(targetAssessmentId)
                .target(request.getHost() != null && !request.getHost().isBlank() ? request.getHost() : domain)
                .profile(com.example.backend.modules.scan.ScanProfile.FULL_COMPREHENSIVE_SCAN)
                .commandLine("bloodhound-ad-collector --domain " + domain + " --host " + request.getHost() + " --user " + finalAuthUser)
                .status(com.example.backend.modules.scan.ScanStatus.COMPLETED)
                .parsedSummary(summaryJson)
                .aiExplanation(summary.getAiAnalysis())
                .completedAt(java.time.LocalDateTime.now())
                .build();
        com.example.backend.modules.scan.ScanTask savedTask = scanTaskRepository.save(newTask);

        Map<String, Object> resp = new HashMap<>();
        resp.put("taskId", savedTask.getId());
        resp.put("assessmentId", savedTask.getAssessmentId());
        resp.put("createdAt", savedTask.getCreatedAt());
        resp.put("domain", domain);
        resp.put("rawJson", jsonContent);
        resp.put("summary", summary);
        resp.put("authenticatedUser", finalAuthUser);
        resp.put("hasValidCredentials", true);
        resp.put("liveCollector", true);
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/scan-and-attach-to-task/{taskId}")
    public ResponseEntity<?> scanAndAttachBloodhoundToTask(
            @PathVariable Long taskId,
            @RequestBody AdScanRequestDto request) {
        try {
            if (request == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Dữ liệu cấu hình Active Directory không được để trống."));
            }
            if (request.getDomain() == null || request.getDomain().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Tên miền Active Directory (Domain) không được để trống."));
            }
            if (request.getHost() == null || request.getHost().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Địa chỉ máy chủ Domain Controller (Host / IP) không được để trống."));
            }
            if (request.getUsername() == null || request.getUsername().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Tài khoản Active Directory (Username) không được để trống."));
            }
            if (request.getPassword() == null || request.getPassword().isBlank()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Mật khẩu tài khoản Active Directory (Password) không được để trống."));
            }

            log.info("Thu thập trực tiếp đồ thị BloodHound AD cho Task ID: {} [Domain: {}, Host: {}, User: {}]",
                    taskId, request.getDomain(), request.getHost(), request.getUsername());

            String jsonContent = bloodhoundAdCollectorService.collectDomainData(request);
            String attachAuthUser = (request.getUsername() != null && !request.getUsername().isBlank())
                    ? request.getUsername().trim()
                    : "";
            BloodhoundAuditSummaryDto summary = processUnifiedBloodhoundAnalysis(jsonContent, request.getDomain(), request.getHost(), attachAuthUser);

            com.example.backend.modules.scan.ScanTask task = scanTaskRepository.findById(taskId)
                    .orElseThrow(() -> new IllegalArgumentException("Task không tồn tại: " + taskId));

            Map<String, Object> summaryMap = new HashMap<>();
            if (task.getParsedSummary() != null && !task.getParsedSummary().isBlank()) {
                try {
                    summaryMap = objectMapper.readValue(task.getParsedSummary(), Map.class);
                } catch (Exception ignored) {}
            }
            Map<String, Object> reconMap = (Map<String, Object>) summaryMap.getOrDefault("recon", new HashMap<>());
            reconMap.put("bloodhoundAudit", summary);
            reconMap.put("authenticatedUser", attachAuthUser);
            reconMap.put("hasValidCredentials", true);
            summaryMap.put("recon", reconMap);

            try {
                String updatedSummaryJson = objectMapper.writeValueAsString(summaryMap);
                var explanation = llmService.explainScanResult(
                        taskId,
                        task.getTarget(),
                        task.getProfile() != null ? task.getProfile().name() : "FULL_COMPREHENSIVE_SCAN",
                        updatedSummaryJson,
                        task.getRawXmlOutput()
                );
                if (explanation != null) {
                    task.setAiExplanation(objectMapper.writeValueAsString(explanation));
                    summaryMap.put("aiExplanation", explanation);
                }
            } catch (Exception ex) {
                log.warn("Lỗi khi LLM giải thích sau khi attach BloodHound: {}", ex.getMessage());
            }

            task.setParsedSummary(objectMapper.writeValueAsString(summaryMap));
            com.example.backend.modules.scan.ScanTask saved = scanTaskRepository.save(task);
            return ResponseEntity.ok(saved);
        } catch (Exception e) {
            log.error("Lỗi khi quét AD và đính kèm vào Task {}: {}", taskId, e.getMessage());
            String errorMsg = e.getMessage();
            if (errorMsg != null && errorMsg.contains("data 52e")) {
                errorMsg = "Sai tên đăng nhập hoặc mật khẩu Active Directory (Lỗi Windows: data 52e). Hãy kiểm tra lại Username và Password.";
            }
            return ResponseEntity.badRequest().body(Map.of("error", errorMsg != null ? errorMsg : "Lỗi khi kết nối thu thập dữ liệu AD"));
        }
    }
}
