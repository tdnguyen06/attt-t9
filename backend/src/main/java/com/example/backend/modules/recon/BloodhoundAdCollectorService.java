package com.example.backend.modules.recon;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.BasicControl;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

@Service
@Slf4j
public class BloodhoundAdCollectorService {

    private final ObjectMapper objectMapper = new ObjectMapper()
            .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    /**
     * Thu thập dữ liệu trực tiếp từ máy chủ Active Directory qua giao thức LDAP/LDAPS.
     * Hoàn toàn không sử dụng mock data.
     */
    public String collectDomainData(AdScanRequestDto request) {
        if (request == null) {
            throw new IllegalArgumentException("Dữ liệu cấu hình Active Directory không được để trống.");
        }

        if (request.getDomain() == null || request.getDomain().isBlank()) {
            throw new IllegalArgumentException("Tên miền Active Directory (Domain) không được để trống. Ví dụ: corp.local hoặc contoso.com");
        }
        String targetDomain = request.getDomain().trim().toLowerCase();
        String baseDn = (request.getBaseDn() != null && !request.getBaseDn().isBlank())
                ? request.getBaseDn().trim()
                : buildBaseDn(targetDomain);

        String method = (request.getMethod() != null && !request.getMethod().isBlank())
                ? request.getMethod().trim().toUpperCase()
                : "LDAP";

        log.info("Bắt đầu thu thập dữ liệu AD thực tế [Method: {}, Domain: {}, BaseDN: {}]", method, targetDomain, baseDn);

        List<LdifRecord> records = new ArrayList<>();
        String dataSourceInfo = "";

        // Kết nối mạng trực tiếp qua giao thức LDAP / LDAPS tới máy chủ AD DC
        if (request.getHost() == null || request.getHost().isBlank()) {
            throw new IllegalArgumentException("Địa chỉ máy chủ Domain Controller (Host / IP) không được để trống.");
        }
            if (request.getUsername() == null || request.getUsername().isBlank()) {
                throw new IllegalArgumentException("Tài khoản xác thực Active Directory (Username) không được để trống. BloodHound yêu cầu tài khoản miền để truy vấn cây đối tượng và ACLs (Active Directory từ chối Anonymous Bind).");
            }
            if (request.getPassword() == null || request.getPassword().isBlank()) {
                throw new IllegalArgumentException("Mật khẩu tài khoản Active Directory (Password) không được để trống.");
            }

            boolean useSsl = Boolean.TRUE.equals(request.getUseSsl()) || "LDAPS".equals(method);
            String host = request.getHost().trim();
            int port = (request.getPort() != null && request.getPort() > 0)
                    ? request.getPort()
                    : (useSsl ? 636 : 389);

            log.info("Kết nối mạng LDAP trực tiếp tới {}:{} (User: {}, SSL: {})", host, port, request.getUsername(), useSsl);
            try {
                records = queryViaLdap(host, port, useSsl, targetDomain, request.getUsername().trim(), request.getPassword(), baseDn);
                dataSourceInfo = String.format("LDAP Server (%s://%s:%d)", useSsl ? "ldaps" : "ldap", host, port);
            } catch (Exception e) {
                log.error("Lỗi khi kết nối tới LDAP {}:{}: {}", host, port, e.getMessage());
                throw new IllegalStateException(String.format("Không thể kết nối đến máy chủ Active Directory LDAP (%s:%d): %s. Vui lòng kiểm tra lại địa chỉ host, cổng hoặc thông tin xác thực.", host, port, e.getMessage()), e);
            }

        if (records.isEmpty()) {
            throw new IllegalStateException("Không tìm thấy bản ghi người dùng hoặc nhóm nào trong BaseDN: " + baseDn + " trên Domain: " + targetDomain);
        }

        log.info("Thu thập thành công {} đối tượng thực tế từ AD ({})", records.size(), targetDomain);
        return convertLdifToBloodhoundJson(records, targetDomain, dataSourceInfo);
    }

    /**
     * Tương thích ngược
     */
    public String collectLiveDomainData(String domain) {
        throw new UnsupportedOperationException("Thu thập dữ liệu BloodHound Active Directory bắt buộc phải cung cấp đầy đủ Domain Controller Host, Username và Password để xác thực.");
    }

    /**
     * Truy vấn trực tiếp máy chủ Active Directory qua giao thức chuẩn LDAP/LDAPS bằng javax.naming.directory.
     * Bắt buộc xác thực tài khoản (Simple Bind). Không hỗ trợ quét ẩn danh.
     */
    private List<LdifRecord> queryViaLdap(String host, int port, boolean useSsl, String domain, String username, String password, String baseDn) throws Exception {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new IllegalArgumentException("Active Directory không cho phép truy vấn ẩn danh (Anonymous Bind) để bóc tách người dùng và quyền hạn ACLs. Bắt buộc cung cấp Username và Password.");
        }

        Hashtable<String, String> env = new Hashtable<>();
        String url = String.format("%s://%s:%d", useSsl ? "ldaps" : "ldap", host, port);

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put("com.sun.jndi.ldap.connect.timeout", "6000");
        env.put("com.sun.jndi.ldap.read.timeout", "8000");
        env.put(Context.REFERRAL, "ignore");
        // Bắt buộc cấu hình đọc nhị phân cho objectSid, nTSecurityDescriptor và sIDHistory
        env.put("java.naming.ldap.attributes.binary", "objectSid nTSecurityDescriptor sIDHistory");

        if (useSsl) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
            env.put("java.naming.ldap.factory.socket", BlindSSLSocketFactory.class.getName());
        }

        String rawUser = username.trim();
        String netbiosDomain = (domain != null && !domain.isBlank()) ? domain.split("\\.")[0].toUpperCase() : "";

        // Tạo danh sách các định dạng đăng nhập AD tiềm năng theo thứ tự ưu tiên
        List<String> candidatePrincipals = new ArrayList<>();
        if (rawUser.contains("\\") || rawUser.contains("@") || rawUser.toUpperCase().startsWith("CN=")) {
            candidatePrincipals.add(rawUser);
        } else if (rawUser.endsWith("$")) {
            // Tài khoản máy tính (Computer Account) trong Windows AD:
            // Phổ biến nhất là NETBIOS\COMPUTER$ hoặc chính tên nó (Active Directory không hỗ trợ UPN cho máy tính)
            if (!netbiosDomain.isBlank()) candidatePrincipals.add(netbiosDomain + "\\" + rawUser);
            candidatePrincipals.add(rawUser);
            if (domain != null && !domain.isBlank()) candidatePrincipals.add(rawUser + "@" + domain);
        } else {
            // Tài khoản người dùng bình thường:
            if (domain != null && !domain.isBlank()) candidatePrincipals.add(rawUser + "@" + domain);
            if (!netbiosDomain.isBlank()) candidatePrincipals.add(netbiosDomain + "\\" + rawUser);
            candidatePrincipals.add(rawUser);
        }

        LdapContext ctx = null;
        Exception lastConnectEx = null;

        for (String candidate : candidatePrincipals) {
            try {
                env.put(Context.SECURITY_AUTHENTICATION, "simple");
                env.put(Context.SECURITY_PRINCIPAL, candidate);
                env.put(Context.SECURITY_CREDENTIALS, password);
                log.info("Thử xác thực LDAP với Principal: {}", candidate);
                ctx = new InitialLdapContext(env, null);
                log.info("Xác thực LDAP thành công với Principal: {}", candidate);
                break;
            } catch (Exception ex) {
                log.warn("Thử xác thực LDAP với '{}' thất bại: {}", candidate, ex.getMessage());
                lastConnectEx = ex;
            }
        }

        if (ctx == null) {
            throw lastConnectEx != null ? lastConnectEx : new IllegalStateException("Không thể kết nối và xác thực tới máy chủ LDAP.");
        }

        List<LdifRecord> records = new ArrayList<>();

        try {
            // Đặt LDAP Server SD Flags Control OID 1.2.840.113556.1.4.801
            // BER: SEQUENCE { INTEGER 7 } -> 0x30, 0x03, 0x02, 0x01, 0x07 (Owner, Group, DACL)
            try {
                Control sdFlagsControl = new BasicControl("1.2.840.113556.1.4.801", false, new byte[]{0x30, 0x03, 0x02, 0x01, 0x07});
                ctx.setRequestControls(new Control[]{ sdFlagsControl });
            } catch (Exception ex) {
                log.warn("Không thể gán SD_FLAGS control lên kết nối LDAP: {}", ex.getMessage());
            }

            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                    "sAMAccountName", "userAccountControl", "servicePrincipalName",
                    "memberOf", "member", "description", "adminCount", "distinguishedName",
                    "objectSid", "nTSecurityDescriptor",
                    "objectClass", "msDS-AllowedToDelegateTo", "sIDHistory",
                    "userPassword", "unixUserPassword", "pwdLastSet",
                    "displayName", "cn", "gPCFileSysPath", "trustPartner", "trustDirection", "trustType"
            });

            String filter = "(|(objectClass=user)(objectClass=group)(objectClass=groupPolicyContainer)(objectClass=trustedDomain))";
            NamingEnumeration<SearchResult> results = ctx.search(baseDn, filter, controls);

            while (true) {
                SearchResult sr = null;
                try {
                    if (results == null || !results.hasMore()) {
                        break;
                    }
                    sr = results.next();
                } catch (javax.naming.NamingException ex) {
                    // Active Directory tự động trả về referral continuation reference, tiếp tục duyệt bản ghi tiếp theo
                    log.debug("Bỏ qua referral LDAP: {}", ex.getMessage());
                    continue;
                } catch (Exception ex) {
                    log.warn("Dừng duyệt kết quả LDAP do lỗi: {}", ex.getMessage());
                    break;
                }

                if (sr == null) continue;
                Attributes attrs = sr.getAttributes();
                if (attrs == null) continue;

                LdifRecord rec = new LdifRecord();
                rec.dn = sr.getNameInNamespace();

                if (attrs.get("objectClass") != null) {
                    NamingEnumeration<?> ocs = attrs.get("objectClass").getAll();
                    while (ocs.hasMore()) {
                        rec.objectClasses.add(ocs.next().toString().toLowerCase());
                    }
                }

                if (attrs.get("sAMAccountName") != null) {
                    rec.sAMAccountName = attrs.get("sAMAccountName").get().toString();
                } else if (attrs.get("displayName") != null) {
                    rec.sAMAccountName = attrs.get("displayName").get().toString();
                } else if (attrs.get("cn") != null) {
                    rec.sAMAccountName = attrs.get("cn").get().toString();
                } else {
                    rec.sAMAccountName = extractCn(rec.dn);
                }

                if (attrs.get("userAccountControl") != null) {
                    rec.userAccountControl = attrs.get("userAccountControl").get().toString();
                }
                if (attrs.get("description") != null) {
                    rec.description = attrs.get("description").get().toString();
                }
                if (attrs.get("adminCount") != null) {
                    rec.adminCount = attrs.get("adminCount").get().toString();
                }

                if (attrs.get("servicePrincipalName") != null) {
                    NamingEnumeration<?> spns = attrs.get("servicePrincipalName").getAll();
                    while (spns.hasMore()) {
                        rec.servicePrincipalNames.add(spns.next().toString());
                    }
                }
                if (attrs.get("memberOf") != null) {
                    NamingEnumeration<?> mems = attrs.get("memberOf").getAll();
                    while (mems.hasMore()) {
                        rec.memberOf.add(mems.next().toString());
                    }
                }
                if (attrs.get("member") != null) {
                    NamingEnumeration<?> mems = attrs.get("member").getAll();
                    while (mems.hasMore()) {
                        rec.members.add(mems.next().toString());
                    }
                }

                if (attrs.get("msDS-AllowedToDelegateTo") != null) {
                    NamingEnumeration<?> dels = attrs.get("msDS-AllowedToDelegateTo").getAll();
                    while (dels.hasMore()) {
                        rec.allowedToDelegateTo.add(dels.next().toString());
                    }
                }

                if (attrs.get("sIDHistory") != null) {
                    NamingEnumeration<?> sids = attrs.get("sIDHistory").getAll();
                    while (sids.hasMore()) {
                        Object sidObj = sids.next();
                        if (sidObj instanceof byte[] sidBytes) {
                            String s = sidBytesToString(sidBytes);
                            if (s != null) rec.sidHistory.add(s);
                        } else if (sidObj != null) {
                            rec.sidHistory.add(sidObj.toString());
                        }
                    }
                }

                if (attrs.get("userPassword") != null || attrs.get("unixUserPassword") != null) {
                    rec.hasPlaintextPassword = true;
                }
                if (attrs.get("pwdLastSet") != null) {
                    rec.pwdLastSet = attrs.get("pwdLastSet").get().toString();
                }
                if (attrs.get("gPCFileSysPath") != null) {
                    rec.gpcPath = attrs.get("gPCFileSysPath").get().toString();
                }
                if (attrs.get("trustPartner") != null) {
                    rec.trustPartner = attrs.get("trustPartner").get().toString();
                }

                if (attrs.get("objectSid") != null) {
                    Object sidObj = attrs.get("objectSid").get();
                    if (sidObj instanceof byte[] sidBytes) {
                        rec.objectSid = sidBytesToString(sidBytes);
                    }
                }

                if (attrs.get("nTSecurityDescriptor") != null) {
                    Object sdObj = attrs.get("nTSecurityDescriptor").get();
                    if (sdObj instanceof byte[] sdBytes) {
                        rec.securityDescriptorBytes = sdBytes;
                    }
                }

                if (rec.sAMAccountName != null && !rec.sAMAccountName.isBlank()) {
                    records.add(rec);
                }
            }
        } finally {
            try {
                ctx.close();
            } catch (Exception ignored) {}
        }

        return records;
    }

    private String buildBaseDn(String domain) {
        String[] parts = domain.split("\\.");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) sb.append(",");
            sb.append("DC=").append(parts[i]);
        }
        return sb.toString();
    }

    /**
     * Chuyển đổi các bản ghi AD thực tế sang chuẩn BloodHound JSON (v5).
     * Bóc tách cả quan hệ thành viên lẫn phân quyền DACL thực tế.
     */
    private String convertLdifToBloodhoundJson(List<LdifRecord> records, String domain, String sourceDescription) {
        ObjectNode root = objectMapper.createObjectNode();
        ArrayNode dataArray = objectMapper.createArrayNode();
        String domainUpper = domain.toUpperCase();

        // Tập hợp danh sách các nhóm quản trị tối cao (Tier 0)
        Set<String> tier0GroupNames = Set.of(
                "DOMAIN ADMINS", "ADMINISTRATORS", "ENTERPRISE ADMINS",
                "SCHEMA ADMINS", "ACCOUNT OPERATORS", "BACKUP OPERATORS"
        );

        // Map tên CN sang sAMAccountName để tra cứu quan hệ
        Map<String, String> dnToSamMap = new HashMap<>();
        Map<String, String> sidToSamMap = new HashMap<>();

        for (LdifRecord rec : records) {
            if (rec.sAMAccountName != null) {
                String samUpper = rec.sAMAccountName.toUpperCase();
                if (rec.dn != null) {
                    dnToSamMap.put(rec.dn.toLowerCase(), samUpper);
                }
                if (rec.objectSid != null) {
                    sidToSamMap.put(rec.objectSid, samUpper);
                }
            }
        }

        // Bảng ánh xạ các SID Built-in phổ biến của Windows
        Map<String, String> wellKnownSids = Map.of(
                "S-1-5-32-544", "ADMINISTRATORS",
                "S-1-5-32-545", "USERS",
                "S-1-5-32-548", "ACCOUNT OPERATORS",
                "S-1-5-32-549", "SERVER OPERATORS",
                "S-1-5-32-551", "BACKUP OPERATORS",
                "S-1-5-18", "NT AUTHORITY\\SYSTEM",
                "S-1-5-11", "NT AUTHORITY\\AUTHENTICATED USERS",
                "S-1-1-0", "EVERYONE",
                "S-1-5-10", "NT AUTHORITY\\SELF"
        );

        for (LdifRecord rec : records) {
            ObjectNode objNode = objectMapper.createObjectNode();
            ObjectNode props = objectMapper.createObjectNode();
            ArrayNode aces = objectMapper.createArrayNode();

            String samUpper = rec.sAMAccountName.toUpperCase();
            String fullPrincipal = samUpper + "@" + domainUpper;

            // 1. Phân tích UserAccountControl
            int uac = 512;
            if (rec.userAccountControl != null) {
                try {
                    uac = Integer.parseInt(rec.userAccountControl);
                } catch (Exception ignored) {}
            }

            boolean isComputer = samUpper.endsWith("$");
            boolean isAccountDisabled = (uac & 0x0002) != 0;
            boolean dontReqPreauth = (uac & 0x400000) != 0; // AS-REP Roasting flag
            boolean hasSpn = !isComputer && !rec.servicePrincipalNames.isEmpty(); // Kerberoasting flag
            boolean isPasswordNotRequired = (uac & 0x0020) != 0; // PASSWD_NOTREQD
            boolean isDontExpirePassword = (uac & 0x10000) != 0; // DONT_EXPIRE_PASSWORD
            boolean isUnconstrainedDelegation = (uac & 0x80000) != 0; // TRUSTED_FOR_DELEGATION
            boolean isTrustedToAuthForDelegation = (uac & 0x1000000) != 0; // Constrained Delegation
            boolean isGpo = rec.objectClasses.contains("grouppolicycontainer") || rec.gpcPath != null;
            boolean isDomainTrust = rec.objectClasses.contains("trusteddomain") || rec.trustPartner != null;
            boolean isGroup = rec.objectClasses.contains("group");
            String objectType = isGpo ? "GPO" : (isDomainTrust ? "Domain" : (isGroup ? "Group" : (isComputer ? "Computer" : "User")));

            // Kiểm tra quản trị viên
            boolean isAdmin = "1".equals(rec.adminCount) ||
                    samUpper.equals("ADMIN") ||
                    samUpper.equals("ADMINISTRATOR") ||
                    samUpper.contains("ADMIN") ||
                    tier0GroupNames.contains(samUpper);

            for (String groupDn : rec.memberOf) {
                String grpUpper = extractCn(groupDn).toUpperCase();
                if (tier0GroupNames.contains(grpUpper)) {
                    isAdmin = true;
                    break;
                }
            }

            props.put("name", fullPrincipal);
            props.put("type", objectType);
            props.put("enabled", !isAccountDisabled);
            props.put("admincount", isAdmin);
            props.put("hasspn", hasSpn);
            props.put("dontreqpreauth", dontReqPreauth);
            props.put("passwordnotreqd", isPasswordNotRequired);
            props.put("dontexpirepassword", isDontExpirePassword);
            props.put("unconstraineddelegation", isUnconstrainedDelegation);
            props.put("trustedtoauthfordelegation", isTrustedToAuthForDelegation);
            props.put("uac", uac);
            if (rec.objectSid != null) {
                props.put("objectsid", rec.objectSid);
            }

            if (!rec.allowedToDelegateTo.isEmpty()) {
                ArrayNode arr = objectMapper.createArrayNode();
                rec.allowedToDelegateTo.forEach(arr::add);
                props.set("allowedtodelegate", arr);
            }
            if (!rec.sidHistory.isEmpty()) {
                ArrayNode arr = objectMapper.createArrayNode();
                rec.sidHistory.forEach(arr::add);
                props.set("sidhistory", arr);
            }
            if (rec.hasPlaintextPassword) {
                props.put("hascleartextpassword", true);
            }
            if (rec.pwdLastSet != null) {
                props.put("pwdlastset", rec.pwdLastSet);
            }
            if (rec.gpcPath != null) {
                props.put("gpcpath", rec.gpcPath);
            }
            if (rec.trustPartner != null) {
                props.put("trustpartner", rec.trustPartner);
            }

            StringBuilder descBuilder = new StringBuilder();
            if (rec.description != null && !rec.description.isBlank()) {
                descBuilder.append(rec.description);
            }
            if (hasSpn) {
                if (!descBuilder.isEmpty()) descBuilder.append(" | ");
                descBuilder.append("SPNs: ").append(String.join(", ", rec.servicePrincipalNames));
            }
            if (dontReqPreauth) {
                if (!descBuilder.isEmpty()) descBuilder.append(" | ");
                descBuilder.append("Pre-Authentication bị tắt (DONT_REQ_PREAUTH)");
            }
            if (!rec.allowedToDelegateTo.isEmpty()) {
                if (!descBuilder.isEmpty()) descBuilder.append(" | ");
                descBuilder.append("Constrained Delegation tới: ").append(String.join(", ", rec.allowedToDelegateTo));
            }
            props.put("description", descBuilder.toString());

            // 2. Xây dựng ma trận phân quyền thực tế từ MemberOf & Member
            for (String groupDn : rec.memberOf) {
                String grpName = extractCn(groupDn).toUpperCase() + "@" + domainUpper;
                ObjectNode ace = objectMapper.createObjectNode();
                ace.put("PrincipalName", fullPrincipal);
                ace.put("PrincipalType", "User");
                ace.put("RightName", "MemberOf");
                ace.put("TargetName", grpName);
                aces.add(ace);
            }

            for (String memberDn : rec.members) {
                String memberSam = dnToSamMap.getOrDefault(memberDn.toLowerCase(), extractCn(memberDn).toUpperCase());
                String memberPrincipal = memberSam + "@" + domainUpper;
                ObjectNode ace = objectMapper.createObjectNode();
                ace.put("PrincipalName", memberPrincipal);
                ace.put("PrincipalType", "User");
                ace.put("RightName", "MemberOf");
                ace.put("TargetName", fullPrincipal);
                aces.add(ace);
            }

            // 3. Phân tích phân quyền DACL thực tế từ nTSecurityDescriptor
            if (rec.securityDescriptorBytes != null) {
                List<RawAce> rawAces = parseSecurityDescriptor(rec.securityDescriptorBytes);
                for (RawAce rawAce : rawAces) {
                    String rightName = determineRightName(rawAce);
                    if (rightName == null) continue;

                    String trusteeSid = rawAce.trusteeSid;
                    // Bỏ qua SYSTEM hoặc SELF để tránh nhiễu hệ thống mặc định
                    if ("S-1-5-18".equals(trusteeSid) || "S-1-5-10".equals(trusteeSid)) {
                        continue;
                    }

                    String trusteeSam = sidToSamMap.get(trusteeSid);
                    if (trusteeSam == null) {
                        trusteeSam = wellKnownSids.get(trusteeSid);
                    }
                    if (trusteeSam == null) {
                        trusteeSam = trusteeSid;
                    }

                    // Bỏ qua quyền trên chính mình (Self-permission)
                    if (trusteeSam.equalsIgnoreCase(samUpper)) {
                        continue;
                    }

                    // Lọc bỏ các nhóm dịch vụ nền mặc định của Windows AD gây nhiễu ma trận quyền
                    String trusteeUpper = trusteeSam.toUpperCase();
                    if (trusteeUpper.contains("TERMINAL SERVER") ||
                            trusteeUpper.contains("CERT PUBLISHERS") ||
                            trusteeUpper.contains("KEY ADMINS") ||
                            trusteeUpper.equals("EVERYONE") ||
                            trusteeUpper.contains("AUTHENTICATED USERS")) {
                        continue;
                    }

                    String trusteePrincipal = (trusteeSam.contains("@") || trusteeSam.contains("\\") || trusteeSam.startsWith("S-1-"))
                            ? trusteeSam
                            : (trusteeSam + "@" + domainUpper);

                    ObjectNode ace = objectMapper.createObjectNode();
                    ace.put("PrincipalName", trusteePrincipal);
                    ace.put("PrincipalType", "User");
                    ace.put("RightName", rightName);
                    ace.put("TargetName", fullPrincipal);
                    aces.add(ace);
                }
            }

            objNode.set("Properties", props);
            objNode.set("Aces", aces);
            dataArray.add(objNode);
        }

        root.set("data", dataArray);

        ObjectNode meta = objectMapper.createObjectNode();
        meta.put("methods", 15);
        meta.put("type", "users,groups");
        meta.put("count", records.size());
        meta.put("version", 5);
        meta.put("domain", domain);
        meta.put("source", sourceDescription != null ? sourceDescription : "Live Active Directory Query");
        meta.put("collectedAt", new Date().toString());
        root.set("meta", meta);

        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(root);
        } catch (Exception e) {
            return root.toString();
        }
    }

    private String extractCn(String dn) {
        if (dn == null) return "Unknown";
        String[] parts = dn.split(",");
        for (String p : parts) {
            p = p.trim();
            if (p.toUpperCase().startsWith("CN=")) {
                return p.substring(3).trim();
            }
        }
        return dn;
    }

    /**
     * Chuyển đổi mảng byte SID của Windows sang chuỗi SID chuẩn (S-1-5-21-...).
     */
    public static String sidBytesToString(byte[] sidBytes) {
        if (sidBytes == null || sidBytes.length < 8) return null;
        ByteBuffer bb = ByteBuffer.wrap(sidBytes).order(ByteOrder.LITTLE_ENDIAN);
        byte revision = bb.get();
        int subAuthorityCount = bb.get() & 0xFF;

        long authority = 0;
        for (int i = 0; i < 6; i++) {
            authority = (authority << 8) | (bb.get() & 0xFF);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("S-").append(revision & 0xFF).append("-").append(authority);

        for (int i = 0; i < subAuthorityCount; i++) {
            if (bb.remaining() >= 4) {
                long subAuth = bb.getInt() & 0xFFFFFFFFL;
                sb.append("-").append(subAuth);
            }
        }
        return sb.toString();
    }

    /**
     * Chuyển đổi 16 byte GUID của Windows Active Directory sang chuỗi GUID (8-4-4-4-12)
     */
    public static String bytesToGuidString(byte[] guidBytes) {
        if (guidBytes == null || guidBytes.length < 16) return null;
        ByteBuffer bb = ByteBuffer.wrap(guidBytes).order(ByteOrder.LITTLE_ENDIAN);
        int data1 = bb.getInt();
        short data2 = bb.getShort();
        short data3 = bb.getShort();

        byte[] data4And5 = new byte[8];
        bb.get(data4And5);

        return String.format("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                data1,
                data2 & 0xFFFF,
                data3 & 0xFFFF,
                data4And5[0] & 0xFF, data4And5[1] & 0xFF,
                data4And5[2] & 0xFF, data4And5[3] & 0xFF, data4And5[4] & 0xFF,
                data4And5[5] & 0xFF, data4And5[6] & 0xFF, data4And5[7] & 0xFF
        ).toLowerCase();
    }

    /**
     * Phân tích cấu trúc Windows Security Descriptor (MS-DTYP) để trích xuất danh sách ACEs trong DACL.
     */
    public static List<RawAce> parseSecurityDescriptor(byte[] sdBytes) {
        List<RawAce> result = new ArrayList<>();
        if (sdBytes == null || sdBytes.length < 20) return result;

        try {
            ByteBuffer bb = ByteBuffer.wrap(sdBytes).order(ByteOrder.LITTLE_ENDIAN);
            short control = bb.getShort(2);
            boolean daclPresent = (control & 0x0004) != 0;
            if (!daclPresent) return result;

            int offsetDacl = bb.getInt(16);
            if (offsetDacl <= 0 || offsetDacl + 8 > sdBytes.length) return result;

            int aceCount = bb.getShort(offsetDacl + 4) & 0xFFFF;
            int currentAceOffset = offsetDacl + 8;

            for (int i = 0; i < aceCount && currentAceOffset + 4 <= sdBytes.length; i++) {
                byte aceType = bb.get(currentAceOffset);
                int aceSize = bb.getShort(currentAceOffset + 2) & 0xFFFF;

                if (aceSize < 4 || currentAceOffset + aceSize > sdBytes.length) break;

                // ACCESS_ALLOWED_ACE_TYPE = 0x00
                if (aceType == 0x00) {
                    if (aceSize >= 8) {
                        int mask = bb.getInt(currentAceOffset + 4);
                        int sidLen = aceSize - 8;
                        byte[] sidBytes = new byte[sidLen];
                        System.arraycopy(sdBytes, currentAceOffset + 8, sidBytes, 0, sidLen);
                        String sidStr = sidBytesToString(sidBytes);
                        if (sidStr != null) {
                            RawAce raw = new RawAce();
                            raw.aceType = aceType;
                            raw.mask = mask;
                            raw.trusteeSid = sidStr;
                            result.add(raw);
                        }
                    }
                }
                // ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
                else if (aceType == 0x05) {
                    if (aceSize >= 12) {
                        int mask = bb.getInt(currentAceOffset + 4);
                        int flags = bb.getInt(currentAceOffset + 8);
                        int curOffset = currentAceOffset + 12;
                        String objectTypeGuid = null;

                        // ACE_OBJECT_TYPE_PRESENT = 0x00000001
                        if ((flags & 0x00000001) != 0 && curOffset + 16 <= currentAceOffset + aceSize) {
                            byte[] guidBytes = new byte[16];
                            System.arraycopy(sdBytes, curOffset, guidBytes, 0, 16);
                            objectTypeGuid = bytesToGuidString(guidBytes);
                            curOffset += 16;
                        }

                        // ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002
                        if ((flags & 0x00000002) != 0 && curOffset + 16 <= currentAceOffset + aceSize) {
                            curOffset += 16;
                        }

                        int sidLen = (currentAceOffset + aceSize) - curOffset;
                        if (sidLen >= 8) {
                            byte[] sidBytes = new byte[sidLen];
                            System.arraycopy(sdBytes, curOffset, sidBytes, 0, sidLen);
                            String sidStr = sidBytesToString(sidBytes);
                            if (sidStr != null) {
                                RawAce raw = new RawAce();
                                raw.aceType = aceType;
                                raw.mask = mask;
                                raw.objectTypeGuid = objectTypeGuid;
                                raw.trusteeSid = sidStr;
                                result.add(raw);
                            }
                        }
                    }
                }

                currentAceOffset += aceSize;
            }
        } catch (Exception e) {
            log.warn("Lỗi khi giải mã Security Descriptor: {}", e.getMessage());
        }

        return result;
    }

    /**
     * Xác định tên quyền BloodHound nguy cơ cao dựa vào Mask và GUID.
     */
    public static String determineRightName(RawAce ace) {
        if (ace == null) return null;

        // 1. Kiểm tra Extended Right theo GUID
        if (ace.objectTypeGuid != null) {
            // User-Force-Change-Password GUID
            if ("00299570-246d-11d0-a765-00a0c911e510".equalsIgnoreCase(ace.objectTypeGuid)) {
                return "ForceChangePassword";
            }
            // Self-Membership (Add Member) GUID
            if ("bf9679c0-0de6-11d0-a285-00aa003049e2".equalsIgnoreCase(ace.objectTypeGuid)) {
                return "AddMember";
            }
        }

        int mask = ace.mask;

        // 2. GenericAll (Full Control)
        if ((mask & 0x10000000) != 0 || (mask & 0x000F01FF) == 0x000F01FF || mask == 0x001F01FF) {
            return "GenericAll";
        }

        // 3. WriteDacl (WRITE_DAC)
        if ((mask & 0x00040000) != 0) {
            return "WriteDacl";
        }

        // 4. WriteOwner (WRITE_OWNER)
        if ((mask & 0x00080000) != 0) {
            return "WriteOwner";
        }

        // 5. AllExtendedRights (RIGHT_DS_CONTROL_ACCESS)
        if ((mask & 0x00000100) != 0 && ace.objectTypeGuid == null) {
            return "AllExtendedRights";
        }

        // 6. GenericWrite / Write Property
        if ((mask & 0x40000000) != 0 || (mask & 0x00000020) != 0) {
            return "GenericWrite";
        }

        return null;
    }

    public static class RawAce {
        public byte aceType;
        public int mask;
        public String objectTypeGuid;
        public String trusteeSid;
    }

    private static class LdifRecord {
        String dn;
        String sAMAccountName;
        String userAccountControl;
        List<String> objectClasses = new ArrayList<>();
        List<String> servicePrincipalNames = new ArrayList<>();
        List<String> memberOf = new ArrayList<>();
        List<String> members = new ArrayList<>();
        List<String> allowedToDelegateTo = new ArrayList<>();
        List<String> sidHistory = new ArrayList<>();
        boolean hasPlaintextPassword = false;
        String pwdLastSet;
        String gpcPath;
        String trustPartner;
        String description;
        String adminCount;
        String objectSid;
        byte[] securityDescriptorBytes;
    }
}
