package com.example.backend.modules.policy;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "security.policy")
@Getter
@Setter
public class SecurityPolicyConfig {

    /**
     * 8.1 Allowlist: Danh sách các công cụ được phép chạy
     */
    private List<String> allowedTools = List.of("nmap");

    /**
     * 8.1 Giới hạn tài nguyên
     */
    private int maxTimeoutSeconds = 600; // 10 phút tối đa cho 1 tác vụ
    private int defaultTimeoutSeconds = 180;
    private int maxConcurrentTasks = 4; // Giới hạn số tác vụ đồng thời
    private int maxMemoryMb = 512; // Giới hạn bộ nhớ container worker
    private int maxOutputSizeKb = 10240; // 10MB kích thước output tối đa
    private boolean enforceApproval = true; // Bắt buộc phê duyệt với bước tác động
}
