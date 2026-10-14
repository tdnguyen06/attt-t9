package com.example.backend.modules.policy;

import com.example.backend.modules.audit.AuditDecision;
import com.example.backend.modules.audit.AuditLogService;
import com.example.backend.modules.planning.PlanStep;
import com.example.backend.modules.scan.ScanProfile;
import com.example.backend.modules.scope.ScopeCheckResult;
import com.example.backend.modules.scope.ScopeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class PolicyEngineServiceImpl implements PolicyEngineService {

    private final SecurityPolicyConfig policyConfig;
    private final ScopeService scopeService;
    private final AuditLogService auditLogService;

    @Override
    public PolicyEvaluationResult evaluateStepExecution(Long assessmentId, PlanStep step, int requestedTimeoutSeconds) {
        List<PolicyViolation> violations = new ArrayList<>();

        ScopeCheckResult scopeCheck = scopeService.verifyTargetInScope(assessmentId, step.getTarget());
        if (!scopeCheck.inScope()) {
            violations.add(new PolicyViolation(
                    "SCOPE_ENFORCEMENT",
                    "CRITICAL",
                    "Mục tiêu '" + step.getTarget() + "' vi phạm chính sách phạm vi: " + scopeCheck.message()
            ));
        }

        boolean toolAllowed = policyConfig.getAllowedTools().stream()
                .anyMatch(t -> t.equalsIgnoreCase(step.getTool()));
        if (!toolAllowed) {
            violations.add(new PolicyViolation(
                    "TOOL_ALLOWLIST",
                    "CRITICAL",
                    "Công cụ '" + step.getTool() + "' không nằm trong danh sách trắng cho phép (" + policyConfig.getAllowedTools() + ")"
            ));
        }

        boolean profileAllowed = Arrays.stream(ScanProfile.values())
                .anyMatch(p -> p.name().equalsIgnoreCase(step.getProfile()));
        if (!profileAllowed) {
            violations.add(new PolicyViolation(
                    "PROFILE_ALLOWLIST",
                    "HIGH",
                    "Profile '" + step.getProfile() + "' không phải là cấu hình quét an toàn được phê chuẩn"
            ));
        }

        if (policyConfig.isEnforceApproval()) {
            if (Boolean.TRUE.equals(step.getRequiresApproval()) && !Boolean.TRUE.equals(step.getIsApproved())) {
                violations.add(new PolicyViolation(
                        "APPROVAL_REQUIRED",
                        "HIGH",
                        "Bước có tác động mức độ '" + step.getImpactLevel() + "' chưa được người quản trị phê duyệt"
                ));
            }
        }

        if (requestedTimeoutSeconds > policyConfig.getMaxTimeoutSeconds()) {
            violations.add(new PolicyViolation(
                    "RESOURCE_LIMIT_TIMEOUT",
                    "MEDIUM",
                    "Thời gian timeout yêu cầu (" + requestedTimeoutSeconds + "s) vượt quá mức tối đa (" + policyConfig.getMaxTimeoutSeconds() + "s)"
            ));
        }

        boolean isAllowed = violations.isEmpty();
        String summaryMessage = isAllowed
                ? "Tất cả chính sách an toàn đều hợp lệ. Cho phép gửi tác vụ tới worker."
                : "Phát hiện " + violations.size() + " vi phạm chính sách an toàn. Từ chối thực thi!";

        auditLogService.log(
                "policy_engine",
                "EVALUATE_POLICY",
                "policy",
                step.getTarget(),
                "StepID=" + step.getId() + ", Tool=" + step.getTool() + ", Profile=" + step.getProfile(),
                isAllowed ? AuditDecision.ALLOWED : AuditDecision.DENIED,
                isAllowed ? "PASS" : "BLOCKED",
                isAllowed ? null : String.join("; ", violations.stream().map(PolicyViolation::message).toList()),
                null
        );

        return new PolicyEvaluationResult(
                isAllowed,
                step.getTarget(),
                step.getTool(),
                step.getProfile(),
                violations,
                summaryMessage
        );
    }
}
