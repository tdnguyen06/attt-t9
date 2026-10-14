package com.example.backend.modules.planning;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "plan_steps")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PlanStep {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "plan_id", nullable = false)
    @JsonBackReference
    private AssessmentPlan plan;

    @Column(name = "step_number", nullable = false)
    private Integer stepNumber;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false, length = 50)
    private String tool; // nmap

    @Column(nullable = false, length = 50)
    private String profile; // QUICK_SCAN, etc.

    @Column(nullable = false, length = 500)
    private String target;

    @Enumerated(EnumType.STRING)
    @Column(name = "impact_level", nullable = false, length = 20)
    private ImpactLevel impactLevel;

    /**
     * Cơ chế Phê duyệt: Hành động có tác động đến máy đích phải được người dùng xác nhận
     */
    @Column(name = "requires_approval", nullable = false)
    @Builder.Default
    private Boolean requiresApproval = false;

    @Column(name = "is_approved", nullable = false)
    @Builder.Default
    private Boolean isApproved = false;

    @Column(name = "approved_by")
    private String approvedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    @Builder.Default
    private StepStatus status = StepStatus.READY;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "expected_outcome", columnDefinition = "TEXT")
    private String expectedOutcome;

    @Column(name = "scan_task_id")
    private Long scanTaskId;

    @Column(name = "result_summary", columnDefinition = "TEXT")
    private String resultSummary;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (requiresApproval == null) {
            requiresApproval = false;
        }
        if (isApproved == null) {
            isApproved = !requiresApproval;
        }
        if (status == null) {
            status = requiresApproval ? StepStatus.PENDING_APPROVAL : StepStatus.READY;
        }
    }
}
