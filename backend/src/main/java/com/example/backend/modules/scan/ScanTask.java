package com.example.backend.modules.scan;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "scan_tasks")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanTask {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "assessment_id", nullable = false)
    private Long assessmentId;

    @Column(name = "step_id")
    private Long stepId;

    @Column(nullable = false)
    private String target; // Target IP/CIDR/Domain

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 50)
    private ScanProfile profile;

    @Column(name = "command_line", nullable = false)
    private String commandLine; // Câu lệnh đã được allowlist hóa

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    @Builder.Default
    private ScanStatus status = ScanStatus.PENDING;

    @Column(name = "raw_xml_output", columnDefinition = "TEXT")
    private String rawXmlOutput; // XML output từ Nmap

    @Column(name = "parsed_summary", columnDefinition = "TEXT")
    private String parsedSummary; // JSON kết quả phân tích cấu trúc

    @Column(name = "ai_explanation", columnDefinition = "TEXT")
    private String aiExplanation; // JSON kết quả giải thích và đề xuất của AI

    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "exit_code")
    private Integer exitCode;

    @Column(name = "duration_ms")
    private Long durationMs;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (status == null) {
            status = ScanStatus.PENDING;
        }
    }
}
