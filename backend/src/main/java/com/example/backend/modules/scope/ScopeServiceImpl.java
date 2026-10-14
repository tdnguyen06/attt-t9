package com.example.backend.modules.scope;

import com.example.backend.modules.audit.AuditDecision;
import com.example.backend.modules.audit.AuditLogService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.net.URI;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class ScopeServiceImpl implements ScopeService {

    private final ScopeRepository scopeRepository;
    private final ScopeValidator scopeValidator;
    private final AuditLogService auditLogService;

    @Override
    @Transactional(readOnly = true)
    public List<ScopeDto> getScopesByAssessmentId(Long assessmentId) {
        return scopeRepository.findByAssessmentId(assessmentId)
                .stream()
                .map(s -> new ScopeDto(s.getId(), s.getTarget(), s.getTargetType(), s.getIsExcluded(), s.getDescription()))
                .toList();
    }

    @Override
    @Transactional
    public ScopeCheckResult verifyTargetInScope(Long assessmentId, String target) {
        List<Scope> scopes = scopeRepository.findByAssessmentId(assessmentId);

        if (scopes.isEmpty()) {
            auditLogService.log("system", "SCOPE_CHECK", "scope", target, "assessmentId=" + assessmentId,
                    AuditDecision.DENIED, "FAILED", "Phiên kiểm thử chưa có mục tiêu được cấu hình", null);
            return new ScopeCheckResult(false, target, null, "Phiên kiểm thử chưa có mục tiêu được cấu hình");
        }

        for (Scope scope : scopes) {
            if (Boolean.TRUE.equals(scope.getIsExcluded())) {
                if (matchesTarget(target, scope.getTarget())) {
                    auditLogService.log("system", "SCOPE_CHECK", "scope", target, "scopeId=" + scope.getId(),
                            AuditDecision.DENIED, "BLOCKED", "Mục tiêu nằm trong danh sách loại trừ (Blacklist)", null);
                    return new ScopeCheckResult(false, target, scope.getTarget(), "Mục tiêu nằm trong danh sách loại trừ (Blacklist)");
                }
            }
        }

        for (Scope scope : scopes) {
            if (!Boolean.TRUE.equals(scope.getIsExcluded())) {
                if (matchesTarget(target, scope.getTarget())) {
                    auditLogService.log("system", "SCOPE_CHECK", "scope", target, "scopeId=" + scope.getId(),
                            AuditDecision.ALLOWED, "SUCCESS", "Mục tiêu hợp lệ trong phạm vi", null);
                    return new ScopeCheckResult(true, target, scope.getTarget(), "Mục tiêu hợp lệ trong phạm vi được cấp phép");
                }
            }
        }

        auditLogService.log("system", "SCOPE_CHECK", "scope", target, "assessmentId=" + assessmentId,
                AuditDecision.DENIED, "OUT_OF_SCOPE", "Mục tiêu nằm ngoài phạm vi được cấp phép", null);
        return new ScopeCheckResult(false, target, null, "CẢNH BÁO: Mục tiêu không nằm trong phạm vi (Out-of-Scope)!");
    }

    private boolean matchesTarget(String target, String declaredScope) {
        if (target.equalsIgnoreCase(declaredScope)) {
            return true;
        }

        if (declaredScope.contains("/")) {
            return scopeValidator.isIpInCidr(target, declaredScope);
        }

        try {
            URI targetUri = URI.create(target.contains("://") ? target : "http://" + target);
            URI declaredUri = URI.create(declaredScope.contains("://") ? declaredScope : "http://" + declaredScope);
            if (targetUri.getHost() != null && declaredUri.getHost() != null) {
                return targetUri.getHost().equalsIgnoreCase(declaredUri.getHost());
            }
        } catch (Exception ignored) {}

        return false;
    }
}
