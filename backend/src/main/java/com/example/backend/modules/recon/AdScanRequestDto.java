package com.example.backend.modules.recon;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdScanRequestDto {
    /**
     * Phương thức thu thập: LDAP, LDAPS, hoặc DOCKER
     */
    private String method;

    /**
     * Tên miền Active Directory (ví dụ: attt.local hoặc corp.internal)
     */
    private String domain;

    /**
     * Địa chỉ IP / Host máy chủ Domain Controller (ví dụ: 127.0.0.1, bore.pub, 192.168.1.100)
     */
    private String host;

    /**
     * Cổng dịch vụ LDAP (mặc định 389 cho LDAP, 636 cho LDAPS)
     */
    private Integer port;

    /**
     * Sử dụng kết nối mã hóa SSL/TLS (LDAPS)
     */
    private Boolean useSsl;

    /**
     * Tên tài khoản / Bind DN (ví dụ: Administrator@attt.local hoặc CN=Administrator,CN=Users,DC=attt,DC=local)
     */
    private String username;

    /**
     * Mật khẩu tài khoản AD
     */
    private String password;

    /**
     * Search Base DN (ví dụ: DC=attt,DC=local - nếu để trống sẽ tự sinh từ domain)
     */
    private String baseDn;

    /**
     * Tên Docker Container (khi chọn thu thập qua Docker, ví dụ: samba-ad-dc)
     */
    private String containerName;

    /**
     * Đường dẫn sam.ldb trong container (mặc định: /var/lib/samba/private/sam.ldb)
     */
    private String samLdbPath;

    /**
     * ID đợt đánh giá (nếu có, để liên kết lưu trữ vào cơ sở dữ liệu)
     */
    private Long assessmentId;
}
