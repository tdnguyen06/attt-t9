package com.example.backend.modules.audit;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "audit_logs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "requester", nullable = false)
    private String requester; // Người dùng hoặc hệ thống yêu cầu

    @Column(name = "action", nullable = false)
    private String action; // Tên hành động (vd: CREATE_ASSESSMENT, RUN_SCAN, APPROVE_STEP, EXECUTE_TASK)

    @Column(name = "module_name", nullable = false)
    private String moduleName; // Tên module (assessment, scope, scan, llm, planning, policy, execution, reporting)

    @Column(name = "target")
    private String target; // Mục tiêu (IP, CIDR, URL)

    @Column(name = "input_data", columnDefinition = "TEXT")
    private String inputData; // Dữ liệu đầu vào

    @Enumerated(EnumType.STRING)
    @Column(name = "decision", nullable = false, length = 30)
    private AuditDecision decision; // ALLOWED, DENIED, APPROVED, EXECUTED, FAILED

    @Column(name = "result_status", length = 50)
    private String resultStatus; // SUCCESS, FAILED, TIMEOUT, REJECTED

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage; // Lỗi nếu có

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (requester == null) {
            requester = "system_user";
        }
    }
}
