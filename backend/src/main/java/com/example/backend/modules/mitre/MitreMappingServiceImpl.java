package com.example.backend.modules.mitre;

import com.example.backend.modules.recon.VulnerabilityFindingDto;
import com.example.backend.modules.reporting.Severity;
import com.example.backend.modules.reporting.VulnerabilityFinding;
import com.example.backend.modules.reporting.VulnerabilityFindingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class MitreMappingServiceImpl implements MitreMappingService {

    private final VulnerabilityFindingRepository findingRepository;

    // Danh mục mẫu các Tactic & Technique chuẩn của Enterprise ATT&CK
    private static final List<TacticTemplate> TACTIC_TEMPLATES = new ArrayList<>();
    private static final Map<String, TechniqueTemplate> TECHNIQUE_CATALOG = new LinkedHashMap<>();

    private record TacticTemplate(String id, String name, String vietnameseName, int order, String description, String icon, String color) {}
    private record TechniqueTemplate(String id, String name, String vietnameseName, String tacticId, String tacticName,
                                      String description, String killChainStage, String exploitationMechanics,
                                      String detectionGuidance, String mitigationGuidance, String url, List<String> sampleCves) {}

    static {
        // 1. TA0043: Reconnaissance (Trinh sát)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0043", "Reconnaissance", "Trinh sát & Thu thập", 1,
                "Thu thập thông tin sơ bộ về mục tiêu, dò quét cổng và nhận diện phiên bản trước khi khai thác.",
                "fa-solid fa-binoculars", "#38bdf8"));

        // 2. TA0001: Initial Access (Tiếp cận ban đầu)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0001", "Initial Access", "Xâm nhập Ban đầu", 2,
                "Khai thác lỗ hổng trên các ứng dụng, máy chủ biên công khai trên Internet để đặt chân vào mạng mục tiêu.",
                "fa-solid fa-door-open", "#f43f5e"));

        // 3. TA0002: Execution (Thực thi mã)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0002", "Execution", "Thực thi Mã Lệnh", 3,
                "Chạy mã lệnh tùy ý của kẻ tấn công trên hệ thống máy chủ hoặc máy trạm mục tiêu.",
                "fa-solid fa-terminal", "#fb923c"));

        // 4. TA0003: Persistence (Duy trì quyền truy cập)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0003", "Persistence", "Duy trì Xâm nhập", 4,
                "Duy trì kết nối ngầm, cắm Web Shell hoặc tạo tài khoản bí mật đề phòng mất quyền.",
                "fa-solid fa-anchor", "#eab308"));

        // 5. TA0004: Privilege Escalation (Leo thang đặc quyền)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0004", "Privilege Escalation", "Leo thang Đặc quyền", 5,
                "Khai thác lỗ hổng Kernel, dịch vụ hoặc Active Directory để nâng quyền lên root hoặc SYSTEM.",
                "fa-solid fa-arrow-trend-up", "#ec4899"));

        // 6. TA0005: Defense Evasion (Né tránh phòng thủ)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0005", "Defense Evasion", "Né tránh Phòng vệ", 6,
                "Mã hóa payload, khai thác driver hoặc bypass WAF, EDR để tránh bị phát hiện.",
                "fa-solid fa-mask", "#a855f7"));

        // 7. TA0006: Credential Access (Chiếm đoạt xác thực)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0006", "Credential Access", "Thu thập Xác thực", 7,
                "Đánh cắp mật khẩu, token, khóa API từ gói tin không mã hóa, bộ nhớ hoặc tệp cấu hình.",
                "fa-solid fa-key", "#6366f1"));

        // 8. TA0007: Discovery (Thám sát nội bộ)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0007", "Discovery", "Thám sát Hệ thống", 8,
                "Dò quét cấu trúc thư mục, phiên bản dịch vụ và các máy chủ khác trong mạng nội bộ.",
                "fa-solid fa-compass", "#14b8a6"));

        // 9. TA0008: Lateral Movement (Di chuyển ngang)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0008", "Lateral Movement", "Di chuyển Ngang", 9,
                "Mở rộng kiểm soát từ máy chủ bàn đạp sang các máy chủ khác qua dịch vụ nội bộ (SMB, RPC, Redis).",
                "fa-solid fa-diagram-project", "#f97316"));

        // 10. TA0040: Impact (Tác động & Phá hoại)
        TACTIC_TEMPLATES.add(new TacticTemplate("TA0040", "Impact", "Tác động & Phá hoại", 10,
                "Làm gián đoạn khả dụng, từ chối dịch vụ (DoS) hoặc phá hủy tính toàn vẹn của hệ thống.",
                "fa-solid fa-skull-crossbones", "#ef4444"));

        // Khởi tạo các Techniques trọng tâm cho từng Tactic
        addTechnique(new TechniqueTemplate("T1592", "Gather Victim Host Information", "Thu thập thông tin máy chủ",
                "TA0043", "Reconnaissance",
                "Kẻ tấn công thu thập thông tin phiên bản phần mềm qua HTTP headers, banner phản hồi hoặc trang tài liệu mở.",
                "1. Reconnaissance",
                "Gửi yêu cầu HTTP HEAD/OPTIONS hoặc kiểm tra Server/X-Powered-By headers để xác định đúng phiên bản lỗi.",
                "Giám sát lưu lượng quét web bất thường, kiểm tra tần suất gọi vào các endpoint nhạy cảm.",
                "Ẩn tiêu đề Server (server_tokens off trong Nginx), không để lộ phiên bản framework.",
                "https://attack.mitre.org/techniques/T1592/",
                List.of("CWE-200")));

        addTechnique(new TechniqueTemplate("T1595", "Active Scanning", "Dò quét dịch vụ chủ động",
                "TA0043", "Reconnaissance",
                "Thực hiện quét cổng TCP/UDP, quét script NSE để phát hiện dịch vụ và lỗ hổng đang mở trên máy chủ.",
                "1. Reconnaissance",
                "Sử dụng công cụ Nmap, Masscan gửi SYN packets đến hàng loạt cổng để xác định trạng thái mở.",
                "Cảnh báo NIDS (Suricata/Snort) với các luật phát hiện TCP SYN Port Scan.",
                "Triển khai Tường lửa giới hạn cổng chỉ cho IP tin cậy, bật Rate-limiting.",
                "https://attack.mitre.org/techniques/T1595/",
                List.of("Nmap Discovery")));

        addTechnique(new TechniqueTemplate("T1190", "Exploit Public-Facing Application", "Khai thác ứng dụng công khai",
                "TA0001", "Initial Access",
                "Khai thác các lỗ hổng bảo mật nghiêm trọng (RCE, Deserialization, SQLi, Path Traversal) trên ứng dụng Web hướng Internet.",
                "2. Initial Access / Weaponization",
                "Gửi payload độc hại qua HTTP Request (Parameter, URI, Header) để ép máy chủ phân tích cú pháp sai và thực thi mã.",
                "Phân tích nhật ký WAF/Web Server tìm kiếm chuỗi mẫu JNDI, OGNL, path traversal '..%2f', payload PHP/JSP.",
                "Cập nhật bản vá định kỳ cho Web Server (Apache, Tomcat, Nginx), ứng dụng WAF và nguyên tắc Zero Trust.",
                "https://attack.mitre.org/techniques/T1190/",
                List.of("CVE-2021-44228", "CVE-2021-41773", "CVE-2021-42013", "CVE-2020-1938", "CVE-2022-22965", "CVE-2024-6387")));

        addTechnique(new TechniqueTemplate("T1189", "Drive-by Compromise", "Xâm nhập qua trang web độc hại",
                "TA0001", "Initial Access",
                "Khai thác lỗ hổng trình duyệt hoặc chèn mã độc vào trang web để tấn công người dùng khi truy cập.",
                "2. Initial Access",
                "Chèn mã JavaScript độc hại lợi dụng việc thiếu CSP hoặc XSS lưu trữ để thực thi mã trên máy nạn nhân.",
                "Kiểm tra CSP violations report, giám sát mã script lạ được nạp từ domain bên ngoài.",
                "Thiết lập tiêu đề Content-Security-Policy (CSP) nghiêm ngặt, bật cờ HttpOnly cho cookie.",
                "https://attack.mitre.org/techniques/T1189/",
                List.of("CWE-1021", "CWE-79")));

        addTechnique(new TechniqueTemplate("T1133", "External Remote Services", "Khai thác dịch vụ từ xa biên",
                "TA0001", "Initial Access",
                "Tận dụng các cổng truy cập từ xa (VPN, RDP, SSH) không có MFA hoặc phiên bản cũ để truy cập trái phép.",
                "2. Initial Access",
                "Dò quét cổng VPN Gateway, thực hiện tấn công brute-force hoặc khai thác lỗ hổng tràn bộ nhớ trên dịch vụ SSH/VPN.",
                "Theo dõi số lần đăng nhập thất bại liên tiếp trên cổng 22, 443, 943 qua SIEM.",
                "Bắt buộc xác thực 2FA/MFA cho toàn bộ kết nối VPN, giới hạn dải IP truy cập quản trị.",
                "https://attack.mitre.org/techniques/T1133/",
                List.of("CVE-2024-6387", "OpenVPN Auth")));

        addTechnique(new TechniqueTemplate("T1059", "Command and Scripting Interpreter", "Thực thi thông dịch lệnh",
                "TA0002", "Execution",
                "Thực thi trực tiếp các câu lệnh hệ thống qua Bash, PowerShell, Python, cmd sau khi tìm thấy điểm chèn lệnh.",
                "3. Execution",
                "Truyền lệnh hệ thống qua Command Injection hoặc qua eval() trong các mô-đun nhúng (như Redis Lua, Spring SpEL).",
                "Giám sát tiến trình con bất thường sinh ra từ Web Server (ví dụ nginx/apache/tomcat gọi /bin/sh hoặc powershell.exe).",
                "Chạy ứng dụng trong sandbox container phi đặc quyền (non-root), hạn chế quyền thực thi các binary hệ điều hành.",
                "https://attack.mitre.org/techniques/T1059/",
                List.of("CVE-2022-0543", "CWE-78")));

        addTechnique(new TechniqueTemplate("T1203", "Exploitation for Client Execution", "Khai thác thực thi phía Client",
                "TA0002", "Execution",
                "Lợi dụng sơ hở trong trình duyệt hoặc phần mềm xử lý dữ liệu của người dùng để thực thi mã kịch bản độc.",
                "3. Execution",
                "Lợi dụng thiếu tiêu đề CSP để thực thi mã khai thác trình duyệt, đánh cắp token hoặc chiếm quyền điều khiển phiên.",
                "Giám sát lỗi CSP reporting, hành vi đánh cắp DOM storage.",
                "Cấu hình CSP, X-Content-Type-Options: nosniff, X-Frame-Options: DENY.",
                "https://attack.mitre.org/techniques/T1203/",
                List.of("CWE-1021", "CVE-2017-11882")));

        addTechnique(new TechniqueTemplate("T1505.003", "Server Software Component: Web Shell", "Cài đặt Web Shell",
                "TA0003", "Persistence",
                "Ghi hoặc tải lên các tệp mã nguồn độc hại (JSP, PHP, ASPX) vào thư mục web công khai để duy trì điều khiển lâu dài.",
                "4. Persistence",
                "Lợi dụng lỗ hổng PUT Upload (CVE-2017-12615) hoặc Path Traversal để ghi tệp shell.jsp vào thư mục webapps.",
                "Giám sát tính toàn vẹn tệp (FIM) trong thư mục web, cảnh báo khi có tệp thực thi mới được tạo.",
                "Đặt quyền thư mục web root là Read-Only đối với tiến trình máy chủ web.",
                "https://attack.mitre.org/techniques/T1505/003/",
                List.of("CVE-2017-12615", "CVE-2024-50379")));

        addTechnique(new TechniqueTemplate("T1068", "Exploitation for Privilege Escalation", "Khai thác leo thang đặc quyền",
                "TA0004", "Privilege Escalation",
                "Lợi dụng lỗ hổng nhân hệ điều hành (Kernel) hoặc cấu hình Active Directory để biến quyền hạn người dùng thấp thành root/SYSTEM.",
                "5. Privilege Escalation",
                "Khai thác lỗ hổng race condition (regreSSHion), lạm dụng quyền ủy quyền Kerberos, DACL trong Active Directory.",
                "Giám sát thay đổi quyền hạn tiến trình (Integrity Level Change), cảnh báo EDR khi user standard gọi API đặc quyền.",
                "Áp dụng nguyên tắc Least Privilege, vá lỗi hệ điều hành và định kỳ rà quét cấu hình Active Directory bằng BloodHound.",
                "https://attack.mitre.org/techniques/T1068/",
                List.of("CVE-2024-6387", "CVE-2022-0847", "BloodHound AD Rights")));

        addTechnique(new TechniqueTemplate("T1211", "Exploitation for Defense Evasion", "Khai thác né tránh phòng thủ",
                "TA0005", "Defense Evasion",
                "Lợi dụng sơ hở trong bộ lọc của WAF hoặc cơ chế kiểm tra bảo mật để payload vượt qua trót lọt.",
                "6. Defense Evasion",
                "Sử dụng mã hóa kép (Double URL Encoding %%32%65), chèn ký tự phân cách lạ để bypass kiểm tra đường dẫn.",
                "Phân tích nhật ký WAF với các chuỗi giải mã bất thường, cảnh báo khi phát hiện %25 hoặc null byte.",
                "Chuẩn hóa dữ liệu đầu vào (Canonicalization) trước khi thực hiện bất kỳ thao tác so khớp đường dẫn nào.",
                "https://attack.mitre.org/techniques/T1211/",
                List.of("CVE-2021-42013", "CVE-2020-0796")));

        addTechnique(new TechniqueTemplate("T1040", "Network Sniffing", "Bắt lén gói tin mạng",
                "TA0006", "Credential Access",
                "Bắt trộm dữ liệu, mật khẩu và phiên đăng nhập khi hệ thống truyền thông điệp qua kênh HTTP không mã hóa.",
                "7. Credential Access",
                "Thực hiện ARP Spoofing hoặc lắng nghe gói tin trên cổng 80/tcp không mã hóa để giải mã mật khẩu truyền dạng Clear-text.",
                "Phát hiện xung đột địa chỉ MAC bất thường trên thiết bị chuyển mạch Switch (Dynamic ARP Inspection).",
                "Bắt buộc mã hóa toàn bộ dữ liệu truyền bằng HTTPS (TLS 1.3), kích hoạt HSTS.",
                "https://attack.mitre.org/techniques/T1040/",
                List.of("CWE-319")));

        addTechnique(new TechniqueTemplate("T1552", "Unsecured Credentials", "Khai thác thông tin xác thực không an toàn",
                "TA0006", "Credential Access",
                "Thu thập mật khẩu, API keys, chuỗi kết nối CSDL bị để lộ trong các tệp sao lưu hoặc endpoint giám sát công khai.",
                "7. Credential Access",
                "Tải tệp admin-backup.zip giải nén lấy mật khẩu, hoặc truy cập /actuator/env để lấy thuộc tính cấu hình chứa Secret Key.",
                "Giám sát các yêu cầu HTTP truy cập vào tệp đuôi .zip, .sql, .env, .bak và các endpoint /actuator.",
                "Không lưu mật khẩu dạng plain-text trong cấu hình, dùng Secret Manager (Vault), đóng các endpoint quản trị.",
                "https://attack.mitre.org/techniques/T1552/",
                List.of("CWE-530", "CVE-2022-22965")));

        addTechnique(new TechniqueTemplate("T1082", "System Information Discovery", "Khám phá thông tin hệ thống",
                "TA0007", "Discovery",
                "Lấy thông tin hệ điều hành, cấu trúc dịch vụ và danh sách API từ tài liệu Swagger UI hoặc thông tin lộ lọt.",
                "8. Discovery",
                "Truy cập /swagger-ui.html để xem toàn bộ danh mục hàm API và tham số nhạy cảm của hệ thống.",
                "Theo dõi truy cập vào các đường dẫn tài liệu API trên môi trường Production.",
                "Tắt Swagger UI trên Production, giới hạn truy cập tài liệu kỹ thuật chỉ trong mạng nội bộ.",
                "https://attack.mitre.org/techniques/T1082/",
                List.of("CWE-200")));

        addTechnique(new TechniqueTemplate("T1083", "File and Directory Discovery", "Dò quét tệp và thư mục",
                "TA0007", "Discovery",
                "Dò quét các thư mục bí mật, giao diện quản trị hoặc tệp cấu hình qua giao thức nội bộ (như Tomcat AJP Ghostcat).",
                "8. Discovery",
                "Gửi yêu cầu AJP13 khai thác Ghostcat đọc bất kỳ tệp nào trong WEB-INF/web.xml của ứng dụng web.",
                "Cảnh báo kết nối tới cổng AJP 8009 từ các địa chỉ IP bên ngoài mạng ứng dụng.",
                "Đóng cổng AJP 8009 nếu không dùng, hoặc đặt secret bắt buộc trong server.xml.",
                "https://attack.mitre.org/techniques/T1083/",
                List.of("CVE-2020-1938")));

        addTechnique(new TechniqueTemplate("T1210", "Exploitation of Remote Services", "Khai thác dịch vụ từ xa",
                "TA0008", "Lateral Movement",
                "Khai thác dịch vụ nội bộ (SMB, RPC, Redis, Database) để nhảy từ máy chủ này sang máy chủ khác mà không cần mật khẩu.",
                "9. Lateral Movement",
                "Gửi payload SMBv1 tràn số nguyên (EternalBlue) hoặc lệnh Redis EVAL nạp thư viện động để chiếm quyền máy chủ nội bộ.",
                "Giám sát lưu lượng SMB/RPC giữa các dải mạng máy trạm, phát hiện payload ghi đè bộ nhớ.",
                "Tắt giao thức cũ (SMBv1), phân đoạn mạng nội bộ (Micro-segmentation), bắt buộc xác thực mật khẩu mạnh cho Redis.",
                "https://attack.mitre.org/techniques/T1210/",
                List.of("CVE-2017-0144", "CVE-2022-0543", "CVE-2015-4335", "CWE-284")));

        addTechnique(new TechniqueTemplate("T1499", "Endpoint Denial of Service", "Từ chối dịch vụ điểm cuối",
                "TA0040", "Impact",
                "Khai thác lỗi tràn bộ nhớ hoặc rò rỉ tài nguyên để làm tê liệt hoặc sập hoàn toàn dịch vụ máy chủ.",
                "10. Impact",
                "Gửi gói tin dị dạng gây lỗi giải phóng bộ nhớ kép hoặc vòng lặp vô hạn làm máy chủ cạn kiệt CPU/RAM.",
                "Giám sát ngưỡng sử dụng CPU, RAM và số lượng kết nối đồng thời đột biến trên máy chủ.",
                "Cài đặt giới hạn kết nối (Rate Limiting), nâng cấp bản vá kernel và service.",
                "https://attack.mitre.org/techniques/T1499/",
                List.of("CVE-2019-0708", "CVE-2023-44487")));
    }

    private static void addTechnique(TechniqueTemplate t) {
        TECHNIQUE_CATALOG.put(t.id(), t);
    }

    @Override
    @Transactional
    public MitreMatrixDto getMitreMatrix() {
        List<VulnerabilityFinding> allFindings = findingRepository.findAll();

        // 1. Tự động cập nhật MITRE tags cho các finding chưa có
        List<VulnerabilityFinding> toSave = new ArrayList<>();
        for (VulnerabilityFinding f : allFindings) {
            if (f.getMitreTechniqueId() == null || f.getMitreTechniqueId().isBlank()) {
                mapFinding(f);
                toSave.add(f);
            }
        }
        if (!toSave.isEmpty()) {
            try {
                findingRepository.saveAll(toSave);
            } catch (Exception e) {
                log.warn("Không thể lưu cập nhật MITRE tags: {}", e.getMessage());
            }
        }

        // 2. Nhóm findings theo Technique ID
        Map<String, List<VulnerabilityFinding>> findingsByTechnique = allFindings.stream()
                .filter(f -> f.getMitreTechniqueId() != null)
                .collect(Collectors.groupingBy(VulnerabilityFinding::getMitreTechniqueId));

        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        int activeTechniquesCount = 0;

        List<MitreTacticDto> tacticDtos = new ArrayList<>();

        for (TacticTemplate tt : TACTIC_TEMPLATES) {
            List<MitreTechniqueDto> techDtos = new ArrayList<>();
            int tacticActiveTech = 0;
            int tacticCritical = 0;
            int tacticHigh = 0;

            for (TechniqueTemplate techTemp : TECHNIQUE_CATALOG.values()) {
                if (!techTemp.tacticId().equals(tt.id())) continue;

                List<VulnerabilityFinding> matchedFindings = findingsByTechnique.getOrDefault(techTemp.id(), Collections.emptyList());
                boolean isActive = !matchedFindings.isEmpty();
                if (isActive) {
                    tacticActiveTech++;
                    activeTechniquesCount++;
                }

                // Xác định mức độ cao nhất
                Severity highestSev = Severity.INFO;
                List<MitreFindingRefDto> findingRefs = new ArrayList<>();

                for (VulnerabilityFinding mf : matchedFindings) {
                    if (mf.getSeverity() != null) {
                        if (mf.getSeverity() == Severity.CRITICAL) {
                            highestSev = Severity.CRITICAL;
                            criticalCount++;
                            tacticCritical++;
                        } else if (mf.getSeverity() == Severity.HIGH && highestSev != Severity.CRITICAL) {
                            highestSev = Severity.HIGH;
                            highCount++;
                            tacticHigh++;
                        } else if (mf.getSeverity() == Severity.MEDIUM && highestSev != Severity.CRITICAL && highestSev != Severity.HIGH) {
                            highestSev = Severity.MEDIUM;
                            mediumCount++;
                        } else if (mf.getSeverity() == Severity.LOW && highestSev == Severity.INFO) {
                            highestSev = Severity.LOW;
                            lowCount++;
                        }
                    }

                    findingRefs.add(MitreFindingRefDto.builder()
                            .id(mf.getId())
                            .title(mf.getTitle())
                            .severity(mf.getSeverity() != null ? mf.getSeverity().name() : "MEDIUM")
                            .target(mf.getTarget())
                            .port(mf.getPort())
                            .serviceName(mf.getServiceName())
                            .cveId(mf.getCveId())
                            .exploitationVector(mf.getExploitationVector())
                            .remediation(mf.getRemediation())
                            .exploitAvailable(mf.getExploitAvailable())
                            .cisaKev(mf.getCisaKev())
                            .build());
                }

                techDtos.add(MitreTechniqueDto.builder()
                        .id(techTemp.id())
                        .name(techTemp.name())
                        .vietnameseName(techTemp.vietnameseName())
                        .tacticId(techTemp.tacticId())
                        .tacticName(techTemp.tacticName())
                        .description(techTemp.description())
                        .killChainStage(techTemp.killChainStage())
                        .exploitationMechanics(techTemp.exploitationMechanics())
                        .detectionGuidance(techTemp.detectionGuidance())
                        .mitigationGuidance(techTemp.mitigationGuidance())
                        .url(techTemp.url())
                        .sampleCves(techTemp.sampleCves())
                        .activeInSystem(isActive)
                        .findingCount(matchedFindings.size())
                        .highestSeverity(isActive ? highestSev.name() : null)
                        .findings(findingRefs)
                        .build());
            }

            tacticDtos.add(MitreTacticDto.builder()
                    .id(tt.id())
                    .name(tt.name())
                    .vietnameseName(tt.vietnameseName())
                    .order(tt.order())
                    .description(tt.description())
                    .icon(tt.icon())
                    .color(tt.color())
                    .techniques(techDtos)
                    .totalTechniques(techDtos.size())
                    .activeTechniquesCount(tacticActiveTech)
                    .criticalFindingsCount(tacticCritical)
                    .highFindingsCount(tacticHigh)
                    .build());
        }

        int totalTechniques = TECHNIQUE_CATALOG.size();
        double coverage = totalTechniques > 0 ? (activeTechniquesCount * 100.0 / totalTechniques) : 0.0;

        return MitreMatrixDto.builder()
                .tactics(tacticDtos)
                .totalTactics(tacticDtos.size())
                .totalTechniquesMonitored(totalTechniques)
                .activeTechniquesDetected(activeTechniquesCount)
                .totalVulnerabilitiesMapped(allFindings.size())
                .matrixCoveragePercent(Math.round(coverage * 10.0) / 10.0)
                .criticalFindingsCount(criticalCount)
                .highFindingsCount(highCount)
                .mediumFindingsCount(mediumCount)
                .lowFindingsCount(lowCount)
                .simulatedAttackPaths(generateSimulatedAttackPaths())
                .build();
    }

    @Override
    public MitreTechniqueDto getTechniqueDetail(String techniqueId) {
        TechniqueTemplate temp = TECHNIQUE_CATALOG.get(techniqueId);
        if (temp == null) {
            throw new IllegalArgumentException("Không tìm thấy Technique ID: " + techniqueId);
        }

        List<VulnerabilityFinding> findings = findingRepository.findAll().stream()
                .filter(f -> techniqueId.equalsIgnoreCase(f.getMitreTechniqueId()))
                .toList();

        List<MitreFindingRefDto> refs = findings.stream()
                .map(f -> MitreFindingRefDto.builder()
                        .id(f.getId())
                        .title(f.getTitle())
                        .severity(f.getSeverity() != null ? f.getSeverity().name() : "MEDIUM")
                        .target(f.getTarget())
                        .port(f.getPort())
                        .serviceName(f.getServiceName())
                        .cveId(f.getCveId())
                        .exploitationVector(f.getExploitationVector())
                        .remediation(f.getRemediation())
                        .exploitAvailable(f.getExploitAvailable())
                        .cisaKev(f.getCisaKev())
                        .build())
                .toList();

        return MitreTechniqueDto.builder()
                .id(temp.id())
                .name(temp.name())
                .vietnameseName(temp.vietnameseName())
                .tacticId(temp.tacticId())
                .tacticName(temp.tacticName())
                .description(temp.description())
                .killChainStage(temp.killChainStage())
                .exploitationMechanics(temp.exploitationMechanics())
                .detectionGuidance(temp.detectionGuidance())
                .mitigationGuidance(temp.mitigationGuidance())
                .url(temp.url())
                .sampleCves(temp.sampleCves())
                .activeInSystem(!refs.isEmpty())
                .findingCount(refs.size())
                .findings(refs)
                .build();
    }

    @Override
    public void mapFinding(VulnerabilityFinding finding) {
        if (finding == null) return;
        MitreMappingResult mapping = resolveMapping(
                finding.getCveId(),
                finding.getTitle(),
                finding.getServiceName(),
                finding.getPort(),
                finding.getDescription(),
                finding.getExploitationVector()
        );

        finding.setMitreTactic(mapping.tacticId + ": " + mapping.tacticName);
        finding.setMitreTechniqueId(mapping.techniqueId);
        finding.setMitreTechniqueName(mapping.techniqueName);
    }

    @Override
    public void mapFindingDto(VulnerabilityFindingDto dto) {
        if (dto == null) return;
        MitreMappingResult mapping = resolveMapping(
                dto.getCveId(),
                dto.getTitle(),
                dto.getCategory(),
                null,
                dto.getDescription(),
                dto.getExploitationVector()
        );

        dto.setMitreTactic(mapping.tacticId + ": " + mapping.tacticName);
        dto.setMitreTechniqueId(mapping.techniqueId);
        dto.setMitreTechniqueName(mapping.techniqueName);
    }

    private record MitreMappingResult(String tacticId, String tacticName, String techniqueId, String techniqueName) {}

    /**
     * Thuật toán ánh xạ thông minh dựa trên CVE, CWE, Dịch vụ và Vector khai thác.
     */
    private MitreMappingResult resolveMapping(String cveId, String title, String service, Integer port, String desc, String exploitVec) {
        String cve = (cveId != null ? cveId : "").toUpperCase(Locale.ROOT);
        String text = ((title != null ? title : "") + " " + (service != null ? service : "") + " " + (desc != null ? desc : "") + " " + (exploitVec != null ? exploitVec : "")).toLowerCase(Locale.ROOT);

        // 1. Ánh xạ trực tiếp theo CVE cụ thể
        if (cve.contains("CVE-2021-44228") || cve.contains("CVE-2021-41773") || cve.contains("CVE-2020-1938")
                || cve.contains("CVE-2017-12615") || cve.contains("CVE-2020-9484") || cve.contains("CVE-2024-50379")
                || cve.contains("CVE-2024-23897") || cve.contains("CVE-2022-22965")) {
            return new MitreMappingResult("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application");
        }

        if (cve.contains("CVE-2024-6387")) {
            return new MitreMappingResult("TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation");
        }

        if (cve.contains("CVE-2017-0144") || cve.contains("CVE-2022-0543") || cve.contains("CVE-2015-4335")) {
            return new MitreMappingResult("TA0008", "Lateral Movement", "T1210", "Exploitation of Remote Services");
        }

        // 2. Ánh xạ theo CWE
        if (cve.contains("CWE-1021") || text.contains("content-security-policy") || text.contains("csp")) {
            return new MitreMappingResult("TA0002", "Execution", "T1203", "Exploitation for Client Execution");
        }
        if (cve.contains("CWE-200") || text.contains("lộ thông tin") || text.contains("swagger") || text.contains("server header")) {
            return new MitreMappingResult("TA0007", "Discovery", "T1082", "System Information Discovery");
        }
        if (cve.contains("CWE-319") || text.contains("không mã hóa") || text.contains("sniffing") || text.contains("luci") || text.contains("clear-text")) {
            return new MitreMappingResult("TA0006", "Credential Access", "T1040", "Network Sniffing");
        }
        if (cve.contains("CWE-530") || text.contains("backup") || text.contains("sao lưu") || text.contains("actuator") || text.contains("secret")) {
            return new MitreMappingResult("TA0006", "Credential Access", "T1552", "Unsecured Credentials");
        }
        if (cve.contains("CWE-284") || text.contains("postgresql") || (port != null && port == 5432)) {
            return new MitreMappingResult("TA0008", "Lateral Movement", "T1210", "Exploitation of Remote Services");
        }

        // 3. Phân loại theo Active Directory / BloodHound
        if (text.contains("active directory") || text.contains("bloodhound") || text.contains("domain admin") || text.contains("dcsync")) {
            return new MitreMappingResult("TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation");
        }

        // 4. Phân loại theo từ khóa nghiệp vụ
        if (text.contains("rce") || text.contains("remote code execution") || text.contains("path traversal") || text.contains("sql injection") || text.contains("unauthenticated")) {
            return new MitreMappingResult("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application");
        }
        if (text.contains("command injection") || text.contains("shell") || text.contains("bash") || text.contains("powershell")) {
            return new MitreMappingResult("TA0002", "Execution", "T1059", "Command and Scripting Interpreter");
        }
        if (text.contains("privilege") || text.contains("leo quyền") || text.contains("root") || text.contains("system")) {
            return new MitreMappingResult("TA0004", "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation");
        }
        if (text.contains("lateral") || text.contains("smb") || text.contains("pivoting") || text.contains("redis")) {
            return new MitreMappingResult("TA0008", "Lateral Movement", "T1210", "Exploitation of Remote Services");
        }
        if (text.contains("dos") || text.contains("denial of service") || text.contains("crash") || text.contains("tràn bộ nhớ")) {
            return new MitreMappingResult("TA0040", "Impact", "T1499", "Endpoint Denial of Service");
        }

        // Mặc định
        return new MitreMappingResult("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application");
    }

    @Override
    public List<AttackPathDto> generateSimulatedAttackPaths() {
        List<VulnerabilityFinding> findings = findingRepository.findAll();
        List<AttackPathDto> paths = new ArrayList<>();

        // 1. Nhóm các lỗ hổng thực tế theo mục tiêu (Target) để tạo chuỗi tấn công THỰC TẾ
        Map<String, List<VulnerabilityFinding>> byTarget = findings.stream()
                .filter(f -> f.getTarget() != null && !f.getTarget().isBlank())
                .collect(Collectors.groupingBy(VulnerabilityFinding::getTarget));

        int pathCounter = 1;
        for (Map.Entry<String, List<VulnerabilityFinding>> entry : byTarget.entrySet()) {
            String target = entry.getKey();
            List<VulnerabilityFinding> targetFindings = entry.getValue();

            List<AttackPathDto.AttackStepDto> steps = new ArrayList<>();
            int stepNum = 1;

            for (VulnerabilityFinding vf : targetFindings) {
                if (vf.getMitreTechniqueId() == null) mapFinding(vf);

                String tacId = "TA0001";
                String tacName = "Initial Access";
                if (vf.getMitreTactic() != null && vf.getMitreTactic().contains(":")) {
                    String[] parts = vf.getMitreTactic().split(":");
                    tacId = parts[0].trim();
                    tacName = parts[1].trim();
                }

                steps.add(AttackPathDto.AttackStepDto.builder()
                        .stepNumber(stepNum++)
                        .tacticId(tacId)
                        .tacticName(tacName)
                        .techniqueId(vf.getMitreTechniqueId() != null ? vf.getMitreTechniqueId() : "T1190")
                        .techniqueName(vf.getMitreTechniqueName() != null ? vf.getMitreTechniqueName() : "Exploit Public-Facing Application")
                        .actionDescription(vf.getTitle())
                        .vulnerabilityUsed(vf.getTitle())
                        .cveId(vf.getCveId())
                        .evidence(vf.getEvidence() != null && !vf.getEvidence().isBlank() ? vf.getEvidence() : "Phát hiện trên " + target)
                        .defenseRecommendation(vf.getRemediation() != null && !vf.getRemediation().isBlank() ? vf.getRemediation() : "Vá lỗi bảo mật.")
                        .build());
            }

            if (!steps.isEmpty()) {
                boolean hasCrit = targetFindings.stream().anyMatch(f -> f.getSeverity() == Severity.CRITICAL);
                boolean hasHigh = targetFindings.stream().anyMatch(f -> f.getSeverity() == Severity.HIGH);
                String risk = hasCrit ? "CRITICAL" : hasHigh ? "HIGH" : "MEDIUM";

                paths.add(AttackPathDto.builder()
                        .id("PATH-0" + pathCounter++)
                        .title("Chuỗi Tấn Công: " + target)
                        .description("Tập hợp " + steps.size() + " kỹ thuật khai thác phát hiện trên mục tiêu " + target)
                        .target(target)
                        .riskLevel(risk)
                        .impactSummary(hasCrit ? "Nguy cơ chiếm quyền điều khiển và thực thi mã từ xa (RCE)" : "Nguy cơ xâm nhập trái phép")
                        .steps(steps)
                        .build());
            }
        }

        // Nếu database chưa có lỗ hổng nào, hiển thị 2 kịch bản kiến trúc mẫu
        if (paths.isEmpty()) {
            paths.add(AttackPathDto.builder()
                    .id("PATH-01")
                    .title("Web Portal -> Root Server")
                    .target("192.168.54.130")
                    .riskLevel("CRITICAL")
                    .impactSummary("Nguy cơ chiếm quyền Root máy chủ CSDL")
                    .steps(List.of(
                            AttackPathDto.AttackStepDto.builder()
                                    .stepNumber(1)
                                    .tacticId("TA0043").tacticName("Reconnaissance")
                                    .techniqueId("T1592").techniqueName("Host Info Gathering")
                                    .actionDescription("Quét web phát hiện Nginx 1.22.1").cveId("CWE-200")
                                    .evidence("Server: nginx/1.22.1").defenseRecommendation("server_tokens off").build(),
                            AttackPathDto.AttackStepDto.builder()
                                    .stepNumber(2)
                                    .tacticId("TA0008").tacticName("Lateral Movement")
                                    .techniqueId("T1210").techniqueName("Exploitation of Remote Services")
                                    .actionDescription("Kết nối Redis 6379 không mật khẩu").cveId("CVE-2015-4335")
                                    .evidence("PING -> PONG").defenseRecommendation("requirepass & bind 127.0.0.1").build()
                    ))
                    .build());
        }

        return paths;
    }
}
