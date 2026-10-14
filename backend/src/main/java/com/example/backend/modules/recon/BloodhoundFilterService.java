package com.example.backend.modules.recon;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@Slf4j
public class BloodhoundFilterService {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final Set<String> HIGH_RISK_ACL_TYPES = Set.of(
            "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
            "ForceChangePassword", "GetChanges", "GetChangesAll",
            "AllExtendedRights", "AddMember", "Owns"
    );

    private static final Set<String> TIER_ZERO_GROUPS = Set.of(
            "DOMAIN ADMINS", "ENTERPRISE ADMINS", "ADMINISTRATORS", "ADMIN", "ADMINISTRATOR",
            "SCHEMA ADMINS", "ACCOUNT OPERATORS", "BACKUP OPERATORS", "DOMAIN CONTROLLERS"
    );

    public BloodhoundAuditSummaryDto filterAndSummarize(String rawBloodhoundJson) {
        return filterAndSummarize(rawBloodhoundJson, null);
    }

    public BloodhoundAuditSummaryDto filterAndSummarize(String rawBloodhoundJson, String authenticatedUser) {
        BloodhoundAuditSummaryDto summary = new BloodhoundAuditSummaryDto();
        if (rawBloodhoundJson == null || rawBloodhoundJson.isBlank()) {
            return summary;
        }

        try {
            JsonNode rootNode = objectMapper.readTree(rawBloodhoundJson);
            List<BloodhoundFindingDto> findings = new ArrayList<>();
            List<String> privilegedAdmins = new ArrayList<>();
            List<String> kerberoastable = new ArrayList<>();
            List<String> asrepRoastable = new ArrayList<>();

            // 1. Process array of objects (Standard BloodHound data format)
            JsonNode dataArray = rootNode.has("data") ? rootNode.get("data") : (rootNode.isArray() ? rootNode : null);

            int totalObjects = 0;
            if (dataArray != null && dataArray.isArray()) {
                totalObjects = dataArray.size();
                for (JsonNode item : dataArray) {
                    processSingleObject(item, findings, privilegedAdmins, kerberoastable, asrepRoastable);
                }
            } else if (rootNode.isObject()) {
                totalObjects = 1;
                processSingleObject(rootNode, findings, privilegedAdmins, kerberoastable, asrepRoastable);
            }

            // 2. Sắp xếp khách quan 100% theo mức độ nghiêm trọng rủi ro chuẩn an toàn thông tin (CRITICAL -> HIGH -> MEDIUM)
            findings.sort((a, b) -> {
                int scoreA = getRiskScore(a.getRiskLevel());
                int scoreB = getRiskScore(b.getRiskLevel());
                return Integer.compare(scoreB, scoreA);
            });

            // 3. Tách các liên kết liên quan đến tài khoản xác thực (nếu có) để người dùng tiện tra cứu
            String authUpper = (authenticatedUser != null) ? authenticatedUser.trim().toUpperCase() : "";
            List<BloodhoundFindingDto> ownedAttackPaths = new ArrayList<>();
            if (!authUpper.isBlank()) {
                for (BloodhoundFindingDto f : findings) {
                    String srcUpper = f.getSourcePrincipal().toUpperCase();
                    if (srcUpper.startsWith(authUpper + "@") || srcUpper.equals(authUpper) || srcUpper.contains("\\" + authUpper)) {
                        ownedAttackPaths.add(f);
                    }
                }
            }

            int critical = 0;
            int high = 0;
            int medium = 0;

            for (BloodhoundFindingDto f : findings) {
                if ("CRITICAL".equalsIgnoreCase(f.getRiskLevel())) critical++;
                else if ("HIGH".equalsIgnoreCase(f.getRiskLevel())) high++;
                else medium++;
            }

            summary.setTotalObjectsScanned(totalObjects);
            summary.setCriticalRiskCount(critical);
            summary.setHighRiskCount(high);
            summary.setMediumRiskCount(medium);
            summary.setHighRiskFindings(findings);
            summary.setOwnedAccountAttackPaths(ownedAttackPaths);
            summary.setPrivilegedAdmins(privilegedAdmins);
            summary.setKerberoastableAccounts(kerberoastable);
            summary.setAsrepRoastableAccounts(asrepRoastable);
            summary.setAuthenticatedUser(authenticatedUser);

            if (rootNode.has("meta") && rootNode.get("meta").has("domain")) {
                summary.setDomainName(rootNode.get("meta").get("domain").asText());
            }

        } catch (Exception e) {
            log.warn("Không thể bóc tách file JSON BloodHound: {}", e.getMessage());
        }

        return summary;
    }

    private static final Map<String, String> DANGEROUS_BUILTIN_GROUPS = Map.of(
            "DNSADMINS", "Nguy cơ tấn công DLL Injection / arbitrary DLL load qua dnscmd để leo quyền SYSTEM trên Domain Controller.",
            "BACKUP OPERATORS", "Có quyền sao lưu toàn bộ hệ thống file, cho phép trích xuất file NTDS.dit và SYSTEM registry để dump toàn bộ hash mật khẩu domain.",
            "SERVER OPERATORS", "Có quyền quản lý dịch vụ hệ thống, nạp driver và can thiệp Domain Controller.",
            "ACCOUNT OPERATORS", "Có quyền tạo, sửa đổi và quản trị tài khoản người dùng và nhóm trong Domain.",
            "PRINT OPERATORS", "Có quyền nạp driver máy in trên Domain Controller (nguy cơ tấn công PrintNightmare)."
    );

    private void processSingleObject(JsonNode item,
                                    List<BloodhoundFindingDto> findings,
                                    List<String> privilegedAdmins,
                                    List<String> kerberoastable,
                                    List<String> asrepRoastable) {
        JsonNode props = item.path("Properties");
        String name = props.path("name").asText(item.path("name").asText("Unknown Object"));
        boolean enabled = props.path("enabled").asBoolean(true);

        // Bỏ qua tài khoản bị vô hiệu hóa để giảm thiểu nhiễu
        if (!enabled) return;

        boolean adminCount = props.path("admincount").asBoolean(false) || props.path("admincount").asInt(0) == 1;
        boolean hasSpn = props.path("hasspn").asBoolean(false);
        boolean dontReqPreauth = props.path("dontreqpreauth").asBoolean(false);

        if (adminCount) {
            privilegedAdmins.add(name);
        }

        boolean isComputerAccount = name.contains("$");
        String nameUpper = name.toUpperCase();

        // 1. Kiểm tra nguy cơ Kerberoasting (Chỉ áp dụng với tài khoản User, bỏ qua tài khoản máy tính)
        if (hasSpn && !isComputerAccount) {
            kerberoastable.add(name);
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType("User")
                    .relationshipType("HasSPN")
                    .riskLevel(adminCount ? "CRITICAL" : "HIGH")
                    .description("Tài khoản dịch vụ có SPN" + (adminCount ? " và thuộc nhóm đặc quyền cao (AdminCount=1)" : ""))
                    .remediation("Chuyển sang tài khoản gMSA (Group Managed Service Account) hoặc áp dụng mật khẩu phức tạp >25 ký tự.")
                    .build());
        }

        // 2. Kiểm tra nguy cơ AS-REP Roasting
        if (dontReqPreauth) {
            asrepRoastable.add(name);
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType("User")
                    .relationshipType("DontReqPreAuth")
                    .riskLevel("HIGH")
                    .description("Tài khoản không yêu cầu xác thực trước Kerberos Pre-Authentication.")
                    .remediation("Kích hoạt lại thuộc tính 'Do not require Kerberos preauthentication' thành False trong ADUC.")
                    .build());
        }

        // 3. Kiểm tra nguy cơ tài khoản không yêu cầu mật khẩu (PASSWD_NOTREQD)
        boolean passwordNotReqd = props.path("passwordnotreqd").asBoolean(false);
        if (passwordNotReqd && !isComputerAccount) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType("User")
                    .relationshipType("PasswdNotRequired")
                    .riskLevel("HIGH")
                    .description("Tài khoản được cấu hình cờ PASSWD_NOTREQD (Không bắt buộc mật khẩu), có nguy cơ mật khẩu rỗng.")
                    .remediation("Gỡ bỏ cờ PASSWD_NOTREQD và áp dụng chính sách mật khẩu phức tạp bắt buộc.")
                    .build());
        }

        // 4. Kiểm tra nguy cơ ủy quyền Kerberos không giới hạn (Unconstrained Delegation)
        boolean unconstrainedDelegation = props.path("unconstraineddelegation").asBoolean(false);
        if (unconstrainedDelegation) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType(isComputerAccount ? "Computer" : "User")
                    .relationshipType("UnconstrainedDelegation")
                    .riskLevel("CRITICAL")
                    .description("Đối tượng được cấp quyền Unconstrained Kerberos Delegation (TRUSTED_FOR_DELEGATION), cho phép kẻ tấn công trích xuất TGT của bất kỳ ai kết nối tới.")
                    .remediation("Chuyển sang Constrained Delegation hoặc Resource-Based Constrained Delegation (RBCD), thêm các tài khoản nhạy cảm vào nhóm Protected Users.")
                    .build());
        }

        // 5. Kiểm tra nguy cơ ủy quyền Kerberos có giới hạn (Constrained Delegation / S4U2Proxy)
        boolean isTrustedToAuth = props.path("trustedtoauthfordelegation").asBoolean(false);
        JsonNode allowedToDel = props.path("allowedtodelegate");
        boolean hasAllowedToDel = allowedToDel.isArray() && !allowedToDel.isEmpty();
        if (isTrustedToAuth || hasAllowedToDel) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType(isComputerAccount ? "Computer" : "User")
                    .relationshipType("ConstrainedDelegation")
                    .riskLevel(isTrustedToAuth ? "CRITICAL" : "HIGH")
                    .description("Đối tượng được cấp quyền Kerberos Constrained Delegation (S4U2Proxy / S4U2Self). Kẻ tấn công có thể mạo danh bất kỳ ai truy cập các dịch vụ đích được ủy quyền.")
                    .remediation("Chuyển sang Resource-Based Constrained Delegation (RBCD), áp dụng cờ 'Account is sensitive and cannot be delegated' trên các tài khoản quản trị.")
                    .build());
        }

        // 6. Kiểm tra lộ mật khẩu dạng rõ (Cleartext Password in Description hoặc UserPassword attribute)
        boolean hasCleartextPwd = props.path("hascleartextpassword").asBoolean(false);
        String desc = props.path("description").asText("");
        String descLower = desc.toLowerCase();
        boolean passwordInDesc = descLower.matches(".*(pass|password|matkhau|pwd|secret)\\s*[:=].*") ||
                descLower.contains("password123") || descLower.contains("matkhau123") || descLower.contains("admin123");
        if (hasCleartextPwd || passwordInDesc) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType(isComputerAccount ? "Computer" : "User")
                    .relationshipType("CleartextPasswordExposed")
                    .riskLevel("CRITICAL")
                    .description("Phát hiện thông tin mật khẩu dạng rõ (Cleartext) hoặc từ khóa mật khẩu nhạy cảm lưu trong thuộc tính hoặc mô tả của đối tượng: " + (hasCleartextPwd ? "[userPassword attribute]" : desc))
                    .remediation("Xóa ngay thông tin mật khẩu khỏi trường mô tả và thuộc tính LDAP, buộc đổi mật khẩu tài khoản lập tức.")
                    .build());
        }

        // 7. Kiểm tra lạm dụng sIDHistory (SID History Abuse / Persistence Backdoor)
        JsonNode sidHistNode = props.path("sidhistory");
        if (sidHistNode.isArray() && !sidHistNode.isEmpty()) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType(isComputerAccount ? "Computer" : "User")
                    .relationshipType("SIDHistoryInjection")
                    .riskLevel("CRITICAL")
                    .description("Tài khoản chứa thuộc tính sIDHistory (" + sidHistNode.toString() + "). Kẻ tấn công có thể tiêm SID đặc quyền (Domain Admins / Enterprise Admins) để duy trì quyền quản trị ngầm.")
                    .remediation("Kiểm tra và xóa các SID không hợp lệ trong thuộc tính sIDHistory bằng PowerShell hoặc ADSI Edit.")
                    .build());
        }

        // 8. Mật khẩu không bao giờ hết hạn trên tài khoản quản trị
        boolean isDontExpire = props.path("dontexpirepassword").asBoolean(false);
        if (isDontExpire && adminCount && !isComputerAccount) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType("User")
                    .relationshipType("PasswordNeverExpires")
                    .riskLevel("HIGH")
                    .description("Tài khoản quản trị viên đặc quyền cao (Tier-0) nhưng được thiết lập 'Password Never Expires' (Mật khẩu không bao giờ hết hạn).")
                    .remediation("Áp dụng chính sách thời hạn mật khẩu tối đa 90 ngày và luân chuyển mật khẩu định kỳ cho tài khoản quản trị.")
                    .build());
        }

        // 9. Tài khoản Guest mặc định còn kích hoạt
        if ((nameUpper.contains("GUEST@") || nameUpper.equals("GUEST") || nameUpper.contains("\\GUEST")) && enabled) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(name)
                    .targetType("User")
                    .relationshipType("GuestAccountEnabled")
                    .riskLevel("HIGH")
                    .description("Tài khoản Guest mặc định đang ở trạng thái KÍCH HOẠT (Enabled), tạo nguy cơ đăng nhập ẩn danh trái phép vào hệ thống mạng AD.")
                    .remediation("Vô hiệu hóa ngay lập tức tài khoản Guest mặc định trong Active Directory Users and Computers (ADUC).")
                    .build());
        }

        // 10. Mối quan hệ tin cậy Domain (Domain Trusts)
        if (props.path("type").asText("").equalsIgnoreCase("Domain") || props.has("trustpartner")) {
            findings.add(BloodhoundFindingDto.builder()
                    .sourcePrincipal(name)
                    .targetObject(props.path("trustpartner").asText(name))
                    .targetType("Domain")
                    .relationshipType("DomainTrust")
                    .riskLevel("MEDIUM")
                    .description("Phát hiện mối quan hệ tin cậy Domain Trust tới đối tác: " + props.path("trustpartner").asText(name) + ". Cần đảm bảo đã kích hoạt SID Filtering (Quarantine) để chống tấn công nhảy miền.")
                    .remediation("Kích hoạt SID Filtering bằng lệnh netdom trust /EnableSIDHistory:no để ngăn chặn leo quyền xuyên domain.")
                    .build());
        }

        // Phân tích quyền ACLs (Aces)
        JsonNode aces = item.path("Aces");
        if (aces.isArray()) {
            for (JsonNode ace : aces) {
                String rightName = ace.path("RightName").asText("");
                String principalType = ace.path("PrincipalType").asText("Object");
                String principalName = ace.path("PrincipalName").asText(name);

                // Lọc bỏ triệt để các dịch vụ hệ thống nền mặc định của Windows
                String princUpper = principalName.toUpperCase();
                if (princUpper.contains("TERMINAL SERVER") ||
                        princUpper.contains("CERT PUBLISHERS") ||
                        princUpper.contains("KEY ADMINS") ||
                        princUpper.equals("EVERYONE") ||
                        princUpper.contains("AUTHENTICATED USERS") ||
                        princUpper.contains("NT AUTHORITY")) {
                    continue;
                }

                // Bỏ qua quyền trên chính mình (Self-permission)
                if (principalName.equalsIgnoreCase(name)) {
                    continue;
                }

                // Phát hiện thành viên trong nhóm nguy hiểm (MemberOf DnsAdmins, Backup Operators...)
                if ("MemberOf".equalsIgnoreCase(rightName)) {
                    String targetUpper = ace.path("TargetName").asText("").toUpperCase();
                    for (Map.Entry<String, String> entry : DANGEROUS_BUILTIN_GROUPS.entrySet()) {
                        if (targetUpper.contains(entry.getKey())) {
                            findings.add(BloodhoundFindingDto.builder()
                                    .sourcePrincipal(principalName)
                                    .targetObject(ace.path("TargetName").asText())
                                    .targetType("Group")
                                    .relationshipType("MemberOfDangerousGroup")
                                    .riskLevel("HIGH")
                                    .description(String.format("Tài khoản '%s' là thành viên của nhóm đặc quyền nguy hiểm '%s': %s", principalName, entry.getKey(), entry.getValue()))
                                    .remediation("Rà soát và loại bỏ các tài khoản người dùng không cần thiết khỏi nhóm " + entry.getKey() + " theo nguyên tắc đặc quyền tối thiểu.")
                                    .build());
                        }
                    }
                }

                // Phát hiện chiếm quyền GPO (GPO Takeover / GPO Abuse)
                boolean isTargetGpo = props.path("type").asText("").equalsIgnoreCase("GPO") ||
                        nameUpper.contains("CN={") || nameUpper.contains("POLICIES");
                if (isTargetGpo && HIGH_RISK_ACL_TYPES.contains(rightName) && !isTierZero(principalName)) {
                    findings.add(BloodhoundFindingDto.builder()
                            .sourcePrincipal(principalName)
                            .targetObject(name)
                            .targetType("GPO")
                            .relationshipType("GPOAbuse")
                            .riskLevel("CRITICAL")
                            .description(String.format("Tài khoản '%s' có quyền '%s' trên Group Policy Object (GPO) '%s'. Kẻ tấn công có thể chèn script độc hại/Scheduled Task thực thi quyền SYSTEM trên toàn bộ máy tính trong Domain.", principalName, rightName, name))
                            .remediation("Thu hồi quyền can thiệp GPO từ các tài khoản không thuộc Domain Admins.")
                            .build());
                }

                if (HIGH_RISK_ACL_TYPES.contains(rightName)) {
                    boolean isTargetTier0 = adminCount || isTierZero(name);
                    boolean isSourceTier0 = isTierZero(principalName);

                    // Nếu nguồn đã là nhóm/tài khoản đặc quyền tối cao (Domain Admin, Administrators...) thì việc có quyền quản trị là thiết kế mặc định của Windows, không phải lỗ hổng leo quyền
                    if (isSourceTier0) {
                        continue;
                    }

                    String riskLevel = isTargetTier0 ? "CRITICAL" : "HIGH";

                    findings.add(BloodhoundFindingDto.builder()
                            .sourcePrincipal(principalName)
                            .targetObject(name)
                            .targetType(principalType)
                            .relationshipType(rightName)
                            .riskLevel(riskLevel)
                            .description(String.format("Quyền '%s' cho phép %s kiểm soát hoặc can thiệp đối tượng '%s'", rightName, principalName, name))
                            .remediation(String.format("Gỡ bỏ quyền ACL dư thừa '%s' trên đối tượng '%s' theo nguyên tắc đặc quyền tối thiểu.", rightName, name))
                            .build());
                }
            }
        }
    }

    private boolean isTierZero(String objectName) {
        if (objectName == null) return false;
        String upper = objectName.toUpperCase();
        if (upper.startsWith("ADMIN@") || upper.startsWith("ADMIN.") || upper.startsWith("ADMIN_") || upper.equals("ADMIN")) {
            return true;
        }
        return TIER_ZERO_GROUPS.stream().anyMatch(upper::contains);
    }

    private int getRiskScore(String level) {
        if ("CRITICAL".equalsIgnoreCase(level)) return 4;
        if ("HIGH".equalsIgnoreCase(level)) return 3;
        if ("MEDIUM".equalsIgnoreCase(level)) return 2;
        return 1;
    }

    public String buildComprehensiveAiPrompt(String rawJson, BloodhoundAuditSummaryDto summary, String domain, String host, String authUser) {
        StringBuilder sb = new StringBuilder();
        sb.append("BẠN LÀ CHUYÊN GIA CAO CẤP VỀ AN TOÀN THÔNG TIN & ĐỒ THỊ PHÂN QUYỀN ACTIVE DIRECTORY (CHIEF AD SECURITY AUDITOR & BLOODHOUND SPECIALIST).\n\n");
        sb.append("Dưới đây là TOÀN BỘ dữ liệu cấu trúc đối tượng, thuộc tính tài khoản và ma trận phân quyền (ACLs/DACLs) được trích xuất từ Active Directory của mục tiêu:\n");
        if (domain != null && !domain.isBlank()) sb.append("- Tên miền (Domain): ").append(domain).append("\n");
        if (host != null && !host.isBlank()) sb.append("- Máy chủ Domain Controller (DC): ").append(host).append("\n");
        if (authUser != null && !authUser.isBlank()) {
            sb.append("- Tài khoản người kiểm thử đang nắm giữ: ").append(authUser).append(" (Đã xác thực thành công)\n");
        }
        sb.append("\n=== TỔNG QUAN DỮ LIỆU ĐÃ TRÍCH XUẤT ===\n");
        if (summary != null) {
            sb.append(String.format("- Tổng số đối tượng quét: %d\n", summary.getTotalObjectsScanned()));
            if (!summary.getPrivilegedAdmins().isEmpty()) {
                sb.append("- Nhóm/Tài khoản đặc quyền cao (Tier-0): ").append(String.join(", ", summary.getPrivilegedAdmins())).append("\n");
            }
            if (!summary.getKerberoastableAccounts().isEmpty()) {
                sb.append("- Tài khoản dịch vụ SPN (Nguy cơ Kerberoasting): ").append(String.join(", ", summary.getKerberoastableAccounts())).append("\n");
            }
            if (!summary.getAsrepRoastableAccounts().isEmpty()) {
                sb.append("- Tài khoản tắt Pre-Auth (Nguy cơ AS-REP Roasting): ").append(String.join(", ", summary.getAsrepRoastableAccounts())).append("\n");
            }
            if (!summary.getHighRiskFindings().isEmpty()) {
                sb.append("- Toàn bộ các liên kết quyền hạn (ACLs/DACLs) quan trọng trong hệ thống:\n");
                for (BloodhoundFindingDto f : summary.getHighRiskFindings()) {
                    sb.append(String.format("  * [%s] %s -> (%s) -> %s: %s\n", f.getRiskLevel(), f.getSourcePrincipal(), f.getRelationshipType(), f.getTargetObject(), f.getDescription()));
                }
            }
        }

        // Đính kèm dữ liệu thô (nếu dung lượng hợp lý <= 120KB) để AI có đầy đủ thuộc tính chi tiết
        if (rawJson != null && !rawJson.isBlank()) {
            String trimmedJson = rawJson.trim();
            if (trimmedJson.length() <= 120000) {
                sb.append("\n=== CHI TIẾT DỮ LIỆU ĐỒ THỊ ACTIVE DIRECTORY (JSON) ===\n```json\n");
                sb.append(trimmedJson);
                sb.append("\n```\n");
            }
        }

        sb.append("\n=== YÊU CẦU PHÂN TÍCH CHUYÊN SÂU TỪ AI (KHÔNG BỊ GIỚI HẠN BỞI BẤT KỲ QUY TẮC CỨNG NÀO) ===\n");
        sb.append("Hãy tự mình đánh giá toàn diện toàn bộ dữ liệu trên để phát hiện TẤT CẢ các rủi ro bảo mật:\n");
        sb.append("1. PHÂN TÍCH VÀ PHÁT HIỆN TOÀN BỘ LỖ HỔNG:\n");
        sb.append("   - Chuỗi leo thang đặc quyền (Privilege Escalation): từ tài khoản thường lên Domain Admin / Tier-0.\n");
        sb.append("   - Kỹ thuật tấn công Kerberos: Kerberoasting, AS-REP Roasting, Delegation (Unconstrained/Constrained Delegation).\n");
        sb.append("   - Quyền hạn nguy hiểm (DACLs): GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword, AddMember,...\n");
        sb.append("   - Vệ sinh tài khoản: PASSWD_NOTREQD, mật khẩu không hết hạn, tài khoản quản trị ngoài Protected Users.\n");
        sb.append("   - Di chuyển ngang (Lateral Movement) giữa các tài khoản, dịch vụ, máy chủ.\n");
        sb.append("2. TỰ ĐỘNG PHÂN LOẠI MỨC ĐỘ NGUY CƠ: [CRITICAL], [HIGH], [MEDIUM], [LOW] dựa trên khả năng khai thác thực tế.\n");
        sb.append("3. KỊCH BẢN TẤN CÔNG THỰC TẾ (KILL CHAIN): Mô tả chi tiết các bước kẻ tấn công có thể thực hiện từ tài khoản đang nắm giữ.\n");
        sb.append("4. HƯỚNG DẪN CỦNG CỐ BẢO MẬT (AD HARDENING & REMEDIATION): Các bước vá lỗi chi tiết theo nguyên tắc đặc quyền tối thiểu (Least Privilege).\n");
        return sb.toString();
    }

    public String buildCompactPromptSummary(BloodhoundAuditSummaryDto summary) {
        if (summary == null || summary.getTotalObjectsScanned() == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("\n=== TÓM TẮT KIỂM TOÁN ACTIVE DIRECTORY / BLOODHOUND (TIỀN XỬ LÝ LỌC NHIỄU CHUẨN) ===\n");
        if (summary.getDomainName() != null) {
            sb.append("Tên Domain: ").append(summary.getDomainName()).append("\n");
        }
        if (summary.getAuthenticatedUser() != null && !summary.getAuthenticatedUser().isBlank()) {
            sb.append("Tài khoản người kiểm thử đang nắm giữ: ").append(summary.getAuthenticatedUser()).append("\n");
        }
        sb.append(String.format("Tổng số đối tượng quét: %d (Critical: %d, High: %d, Medium: %d)\n",
                summary.getTotalObjectsScanned(), summary.getCriticalRiskCount(), summary.getHighRiskCount(), summary.getMediumRiskCount()));

        if (!summary.getPrivilegedAdmins().isEmpty()) {
            sb.append("- Danh sách tài khoản quản trị đặc quyền cao: ").append(String.join(", ", summary.getPrivilegedAdmins())).append("\n");
        }
        if (!summary.getKerberoastableAccounts().isEmpty()) {
            sb.append("- Tài khoản dịch vụ SPN (Kerberoasting): ").append(String.join(", ", summary.getKerberoastableAccounts())).append("\n");
        }
        if (!summary.getAsrepRoastableAccounts().isEmpty()) {
            sb.append("- Tài khoản Pre-Auth Disabled (AS-REP Roasting): ").append(String.join(", ", summary.getAsrepRoastableAccounts())).append("\n");
        }

        if (!summary.getHighRiskFindings().isEmpty()) {
            sb.append("Toàn bộ các liên kết quyền (ACLs) nguy cơ phát hiện được:\n");
            for (BloodhoundFindingDto f : summary.getHighRiskFindings()) {
                sb.append(String.format("  * [%s] %s -> (%s) -> %s\n", f.getRiskLevel(), f.getSourcePrincipal(), f.getRelationshipType(), f.getTargetObject()));
            }
        } else {
            sb.append("- Không phát hiện liên kết quyền hạn ACL bất thường (như GenericAll, WriteDacl, WriteOwner) trên các đối tượng đã thu thập.\n");
        }
        sb.append("=================================================================================\n");
        return sb.toString();
    }
}
