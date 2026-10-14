package com.example.backend.modules.planning;

import com.example.backend.modules.assessment.Assessment;
import com.example.backend.modules.assessment.AssessmentRepository;
import com.example.backend.modules.assessment.AssessmentStatus;
import com.example.backend.modules.audit.AuditDecision;
import com.example.backend.modules.audit.AuditLogService;
import com.example.backend.modules.llm.LlmPlanSuggestion;
import com.example.backend.modules.llm.LlmStepSuggestion;
import com.example.backend.modules.llm.LlmService;
import com.example.backend.modules.policy.PolicyEvaluationResult;
import com.example.backend.modules.policy.PolicyEngineService;
import com.example.backend.modules.scan.ScanTask;
import com.example.backend.modules.scan.ScanService;
import com.example.backend.modules.scope.Scope;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class PlanningServiceImpl implements PlanningService {

    private final AssessmentPlanRepository planRepository;
    private final PlanStepRepository stepRepository;
    private final AssessmentRepository assessmentRepository;
    private final LlmService llmService;
    private final PolicyEngineService policyEngineService;
    private final ScanService scanService;
    private final AuditLogService auditLogService;

    @Override
    @Transactional
    public AssessmentPlanDto generatePlanForAssessment(Long assessmentId) {
        Assessment assessment = assessmentRepository.findById(assessmentId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy phiên kiểm thử với ID: " + assessmentId));

        List<String> inScopeTargets = assessment.getScopes().stream()
                .filter(s -> !Boolean.TRUE.equals(s.getIsExcluded()))
                .map(Scope::getTarget)
                .toList();

        if (inScopeTargets.isEmpty()) {
            throw new IllegalArgumentException("Không thể lập kế hoạch: Chưa có mục tiêu hợp lệ trong phạm vi");
        }

        LlmPlanSuggestion suggestion = llmService.generateAssessmentPlan(
                assessment.getName(),
                assessment.getType().name(),
                inScopeTargets
        );

        AssessmentPlan plan = AssessmentPlan.builder()
                .assessmentId(assessmentId)
                .title(suggestion.title())
                .summary(suggestion.summary())
                .riskAssessment(suggestion.riskAssessment())
                .status(PlanStatus.DRAFT)
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        int stepNo = 1;
        for (LlmStepSuggestion s : suggestion.steps()) {
            ImpactLevel impact = parseImpact(s.impactLevel());
            boolean reqApproval = s.requiresApproval() || impact == ImpactLevel.HIGH || impact == ImpactLevel.CRITICAL;

            PlanStep step = PlanStep.builder()
                    .plan(plan)
                    .stepNumber(stepNo++)
                    .name(s.name())
                    .tool(s.tool() != null ? s.tool().toLowerCase() : "nmap")
                    .profile(s.profile() != null ? s.profile() : "FULL_COMPREHENSIVE_SCAN")
                    .target(s.target())
                    .impactLevel(impact)
                    .requiresApproval(reqApproval)
                    .isApproved(!reqApproval)
                    .status(reqApproval ? StepStatus.PENDING_APPROVAL : StepStatus.READY)
                    .description(s.description())
                    .expectedOutcome(s.expectedOutcome())
                    .createdAt(LocalDateTime.now())
                    .build();

            plan.getSteps().add(step);
        }

        AssessmentPlan saved = planRepository.save(plan);

        assessment.setStatus(AssessmentStatus.PLANNING);

        auditLogService.log(
                "system",
                "GENERATE_PLAN",
                "planning",
                "AssessmentID=" + assessmentId,
                "PlanID=" + saved.getId() + ", Steps=" + saved.getSteps().size(),
                AuditDecision.ALLOWED,
                "SUCCESS",
                null,
                null
        );

        return toDto(saved);
    }

    @Override
    @Transactional
    public PlanStepDto approveStep(Long stepId, ApproveStepRequest request) {
        PlanStep step = stepRepository.findById(stepId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy bước với ID: " + stepId));

        String approver = request.approvedBy() != null ? request.approvedBy() : "security_lead";

        if (request.approved()) {
            step.setIsApproved(true);
            step.setApprovedBy(approver);
            step.setApprovedAt(LocalDateTime.now());
            step.setStatus(StepStatus.READY);

            auditLogService.log(
                    approver,
                    "APPROVE_STEP",
                    "planning",
                    step.getTarget(),
                    "StepID=" + stepId + ", Tool=" + step.getTool() + ", Impact=" + step.getImpactLevel() + (request.comment() != null ? " Comment: " + request.comment() : ""),
                    AuditDecision.APPROVED,
                    "SUCCESS",
                    null,
                    null
            );
        } else {
            step.setIsApproved(false);
            step.setStatus(StepStatus.REJECTED);

            auditLogService.log(
                    approver,
                    "REJECT_STEP",
                    "planning",
                    step.getTarget(),
                    "StepID=" + stepId + " Rejected" + (request.comment() != null ? " Reason: " + request.comment() : ""),
                    AuditDecision.REJECTED,
                    "REJECTED",
                    request.comment(),
                    null
            );
        }

        PlanStep saved = stepRepository.save(step);
        return toStepDto(saved);
    }

    @Override
    @Transactional
    public AssessmentPlanDto approveAllSteps(Long assessmentId, String approvedBy) {
        AssessmentPlan plan = planRepository.findTopByAssessmentIdOrderByCreatedAtDesc(assessmentId)
                .orElseThrow(() -> new IllegalArgumentException("Chưa có kế hoạch kiểm thử cho Assessment ID: " + assessmentId));

        String approver = approvedBy != null ? approvedBy : "Chuyên viên ATTT";
        for (PlanStep step : plan.getSteps()) {
            step.setIsApproved(true);
            step.setApprovedBy(approver);
            step.setApprovedAt(LocalDateTime.now());
            if (step.getStatus() == StepStatus.PENDING_APPROVAL || step.getStatus() == null) {
                step.setStatus(StepStatus.READY);
            }
            stepRepository.save(step);
        }

        auditLogService.log(approver, "APPROVE_ALL_STEPS", "planning", "AssessmentID=" + assessmentId,
                "Approved all " + plan.getSteps().size() + " steps", AuditDecision.APPROVED, "SUCCESS", null, null);

        return toDto(plan);
    }

    @Override
    @Transactional
    public PlanStepDto executeStep(Long stepId, String executedBy) {
        PlanStep step = stepRepository.findById(stepId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy bước với ID: " + stepId));

        Long assessmentId = step.getPlan().getAssessmentId();

        PolicyEvaluationResult policyResult = policyEngineService.evaluateStepExecution(assessmentId, step, 180);
        if (!policyResult.allowed()) {
            throw new IllegalArgumentException("Từ chối thực thi do vi phạm chính sách an toàn: " + policyResult.summaryMessage());
        }

        ScanTask scanTask = scanService.runScanForPlanStep(step);

        auditLogService.log(
                executedBy != null ? executedBy : "operator",
                "EXECUTE_STEP",
                "planning",
                step.getTarget(),
                "StepID=" + step.getId() + ", ScanTaskID=" + scanTask.getId() + ", Profile=" + step.getProfile(),
                AuditDecision.EXECUTED,
                "RUNNING",
                null,
                null
        );

        return toStepDto(step);
    }

    @Override
    @Transactional
    public AssessmentPlanDto executeAllSteps(Long assessmentId, String executedBy) {
        AssessmentPlan plan = planRepository.findTopByAssessmentIdOrderByCreatedAtDesc(assessmentId)
                .orElseGet(() -> {
                    generatePlanForAssessment(assessmentId);
                    return planRepository.findTopByAssessmentIdOrderByCreatedAtDesc(assessmentId)
                            .orElseThrow(() -> new IllegalStateException("Không thể khởi tạo kế hoạch kiểm thử."));
                });

        String executor = executedBy != null ? executedBy : "Chuyên viên ATTT";

        // Tự động duyệt toàn bộ các bước
        for (PlanStep step : plan.getSteps()) {
            step.setIsApproved(true);
            step.setApprovedBy(executor);
            step.setApprovedAt(LocalDateTime.now());
            if (step.getStatus() == StepStatus.PENDING_APPROVAL || step.getStatus() == null) {
                step.setStatus(StepStatus.READY);
            }
            stepRepository.save(step);
        }

        // Kích hoạt quét đồng thời cho tất cả các mục tiêu
        for (PlanStep step : plan.getSteps()) {
            if (step.getStatus() != StepStatus.RUNNING) {
                try {
                    scanService.runScanForPlanStep(step);
                } catch (Exception e) {
                    log.error("Lỗi khi kích hoạt bước {}: {}", step.getId(), e.getMessage());
                }
            }
        }

        Assessment assessment = assessmentRepository.findById(assessmentId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy phiên kiểm thử với ID: " + assessmentId));
        assessment.setStatus(AssessmentStatus.SCANNING);
        assessmentRepository.save(assessment);

        plan.setStatus(PlanStatus.IN_PROGRESS);
        planRepository.save(plan);

        auditLogService.log(executor, "EXECUTE_ALL_STEPS", "planning", "AssessmentID=" + assessmentId,
                "Executed all " + plan.getSteps().size() + " steps simultaneously", AuditDecision.EXECUTED, "RUNNING", null, null);

        return toDto(plan);
    }

    @Override
    @Transactional(readOnly = true)
    public AssessmentPlanDto getPlanByAssessmentId(Long assessmentId) {
        return planRepository.findTopByAssessmentIdOrderByCreatedAtDesc(assessmentId)
                .map(this::toDto)
                .orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public AssessmentPlanDto getPlanById(Long planId) {
        AssessmentPlan plan = planRepository.findById(planId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy kế hoạch với ID: " + planId));
        return toDto(plan);
    }

    private ImpactLevel parseImpact(String impactStr) {
        if (impactStr == null) return ImpactLevel.LOW;
        try {
            return ImpactLevel.valueOf(impactStr.toUpperCase());
        } catch (Exception e) {
            return ImpactLevel.LOW;
        }
    }

    private AssessmentPlanDto toDto(AssessmentPlan plan) {
        List<PlanStepDto> stepDtos = plan.getSteps().stream()
                .map(this::toStepDto)
                .toList();

        int pendingCount = (int) plan.getSteps().stream()
                .filter(s -> s.getStatus() == StepStatus.PENDING_APPROVAL)
                .count();

        return new AssessmentPlanDto(
                plan.getId(),
                plan.getAssessmentId(),
                plan.getTitle(),
                plan.getSummary(),
                plan.getRiskAssessment(),
                plan.getStatus(),
                stepDtos,
                plan.getSteps().size(),
                pendingCount,
                plan.getCreatedAt(),
                plan.getUpdatedAt()
        );
    }

    private PlanStepDto toStepDto(PlanStep step) {
        return new PlanStepDto(
                step.getId(),
                step.getStepNumber(),
                step.getName(),
                step.getTool(),
                step.getProfile(),
                step.getTarget(),
                step.getImpactLevel(),
                step.getRequiresApproval(),
                step.getIsApproved(),
                step.getApprovedBy(),
                step.getApprovedAt(),
                step.getStatus(),
                step.getDescription(),
                step.getExpectedOutcome(),
                step.getScanTaskId(),
                step.getResultSummary()
        );
    }
}
