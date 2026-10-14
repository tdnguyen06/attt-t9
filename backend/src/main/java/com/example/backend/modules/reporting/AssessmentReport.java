package com.example.backend.modules.reporting;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "assessment_reports")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssessmentReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "assessment_id", nullable = false)
    private Long assessmentId;

    @Column(nullable = false)
    private String title;

    @Column(name = "executive_summary", columnDefinition = "TEXT")
    private String executiveSummary; // Tóm tắt cho lãnh đạo

    @Enumerated(EnumType.STRING)
    @Column(name = "overall_risk", nullable = false, length = 20)
    @Builder.Default
    private Severity overallRisk = Severity.LOW;

    @Column(name = "total_findings", nullable = false)
    @Builder.Default
    private Integer totalFindings = 0;

    @Column(name = "critical_count", nullable = false)
    @Builder.Default
    private Integer criticalCount = 0;

    @Column(name = "high_count", nullable = false)
    @Builder.Default
    private Integer highCount = 0;

    @Column(name = "medium_count", nullable = false)
    @Builder.Default
    private Integer mediumCount = 0;

    @Column(name = "low_count", nullable = false)
    @Builder.Default
    private Integer lowCount = 0;

    @Column(name = "info_count", nullable = false)
    @Builder.Default
    private Integer infoCount = 0;

    @Column(name = "recommendations", columnDefinition = "TEXT")
    private String recommendations;

    @Column(name = "generated_by")
    private String generatedBy;

    @OneToMany(
            mappedBy = "report",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @Builder.Default
    @JsonManagedReference
    private List<VulnerabilityFinding> findings = new ArrayList<>();

    @Column(name = "generated_at", nullable = false)
    private LocalDateTime generatedAt;

    @PrePersist
    public void prePersist() {
        if (generatedAt == null) {
            generatedAt = LocalDateTime.now();
        }
        if (overallRisk == null) {
            overallRisk = Severity.LOW;
        }
    }
}
