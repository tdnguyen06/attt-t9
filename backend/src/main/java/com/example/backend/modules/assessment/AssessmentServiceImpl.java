package com.example.backend.modules.assessment;

import com.example.backend.modules.audit.AuditDecision;
import com.example.backend.modules.audit.AuditLogService;
import com.example.backend.modules.scope.ScopeDto;
import com.example.backend.modules.scope.Scope;
import com.example.backend.modules.scope.ScopeType;
import com.example.backend.modules.scope.ScopeValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AssessmentServiceImpl implements AssessmentService {

    private final AssessmentRepository assessmentRepository;
    private final com.example.backend.modules.scan.ScanTaskRepository scanTaskRepository;
    private final com.example.backend.modules.planning.AssessmentPlanRepository planRepository;
    private final com.example.backend.modules.reporting.AssessmentReportRepository reportRepository;
    private final ScopeValidator scopeValidator;
    private final AuditLogService auditLogService;

    @Override
    @Transactional
    public AssessmentDetailResponse create(CreateAssessmentRequest request) {
        log.info("Creating assessment: {}", request.name());

        for (String target : request.targets()) {
            scopeValidator.validateTarget(request.type().name(), target);
        }

        if (request.excludedTargets() != null) {
            for (String target : request.excludedTargets()) {
                scopeValidator.validateTarget(request.type().name(), target);
            }
        }

        Assessment assessment = Assessment.builder()
                .name(request.name().trim())
                .type(request.type())
                .status(AssessmentStatus.CREATED)
                .description(request.description())
                .createdBy(request.createdBy() != null ? request.createdBy() : "security_analyst")
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();

        for (String target : request.targets()) {
            ScopeType scopeType = determineScopeType(request.type(), target);
            Scope scope = Scope.builder()
                    .assessment(assessment)
                    .target(target.trim())
                    .targetType(scopeType)
                    .isExcluded(false)
                    .build();
            assessment.getScopes().add(scope);
        }

        if (request.excludedTargets() != null) {
            for (String target : request.excludedTargets()) {
                ScopeType scopeType = determineScopeType(request.type(), target);
                Scope scope = Scope.builder()
                        .assessment(assessment)
                        .target(target.trim())
                        .targetType(scopeType)
                        .isExcluded(true)
                        .description("Blacklist / Loại trừ khỏi kiểm thử")
                        .build();
                assessment.getScopes().add(scope);
            }
        }

        Assessment saved = assessmentRepository.save(assessment);

        auditLogService.log(
                saved.getCreatedBy(),
                "CREATE_ASSESSMENT",
                "assessment",
                saved.getName(),
                "targetsCount=" + request.targets().size() + ", type=" + request.type(),
                AuditDecision.ALLOWED,
                "SUCCESS",
                null,
                null
        );

        return toDetailResponse(saved);
    }

    @Override
    @Transactional
    public List<AssessmentResponse> getAll() {
        List<Assessment> list = assessmentRepository.findAllByOrderByCreatedAtDesc();
        for (Assessment a : list) {
            if (a.getStatus() == AssessmentStatus.SCANNING || a.getStatus() == AssessmentStatus.EXECUTING) {
                List<com.example.backend.modules.scan.ScanTask> tasks = scanTaskRepository.findByAssessmentIdOrderByCreatedAtDesc(a.getId());
                if (!tasks.isEmpty() && tasks.stream().allMatch(t -> t.getStatus() == com.example.backend.modules.scan.ScanStatus.COMPLETED || t.getStatus() == com.example.backend.modules.scan.ScanStatus.FAILED)) {
                    a.setStatus(AssessmentStatus.COMPLETED);
                    a.setUpdatedAt(LocalDateTime.now());
                    assessmentRepository.save(a);
                }
            }
        }
        return list.stream()
                .map(this::toSummaryResponse)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public AssessmentDetailResponse getById(Long id) {
        Assessment assessment = findEntityById(id);
        return toDetailResponse(assessment);
    }

    @Override
    @Transactional
    public AssessmentDetailResponse updateStatus(Long id, UpdateStatusRequest request) {
        Assessment assessment = findEntityById(id);
        AssessmentStatus oldStatus = assessment.getStatus();
        assessment.setStatus(request.status());
        assessment.setUpdatedAt(LocalDateTime.now());
        Assessment updated = assessmentRepository.save(assessment);

        auditLogService.log(
                "operator",
                "UPDATE_STATUS",
                "assessment",
                "ID=" + id,
                "oldStatus=" + oldStatus + " -> newStatus=" + request.status() + (request.reason() != null ? " Reason: " + request.reason() : ""),
                AuditDecision.ALLOWED,
                "SUCCESS",
                null,
                null
        );

        return toDetailResponse(updated);
    }

    @Override
    @Transactional
    public void delete(Long id) {
        Assessment assessment = findEntityById(id);
        log.info("Deleting assessment: {} (ID: {})", assessment.getName(), id);

        // Xóa các báo cáo liên quan
        var reports = reportRepository.findByAssessmentId(id);
        if (!reports.isEmpty()) {
            reportRepository.deleteAll(reports);
        }

        // Xóa các kế hoạch liên quan (cascade sẽ xóa PlanStep)
        var plans = planRepository.findByAssessmentId(id);
        if (!plans.isEmpty()) {
            planRepository.deleteAll(plans);
        }

        // Xóa các task quét liên quan
        var tasks = scanTaskRepository.findByAssessmentIdOrderByCreatedAtDesc(id);
        if (!tasks.isEmpty()) {
            scanTaskRepository.deleteAll(tasks);
        }

        // Xóa assessment (cascade sẽ xóa Scopes)
        assessmentRepository.delete(assessment);

        auditLogService.log(
                "operator",
                "DELETE_ASSESSMENT",
                "assessment",
                assessment.getName(),
                "Deleted assessment ID=" + id,
                AuditDecision.ALLOWED,
                "SUCCESS",
                null,
                null
        );
    }

    @Override
    @Transactional(readOnly = true)
    public Assessment findEntityById(Long id) {
        return assessmentRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy phiên kiểm thử với ID: " + id));
    }

    private ScopeType determineScopeType(AssessmentType type, String target) {
        if (type == AssessmentType.WEB) {
            return ScopeType.URL;
        }
        if (target.contains("/")) {
            return ScopeType.CIDR;
        }
        return ScopeType.IP;
    }

    private AssessmentResponse toSummaryResponse(Assessment entity) {
        List<String> targets = entity.getScopes().stream()
                .filter(s -> !Boolean.TRUE.equals(s.getIsExcluded()))
                .map(Scope::getTarget)
                .toList();
        int inScopeCount = targets.size();
        return new AssessmentResponse(
                entity.getId(),
                entity.getName(),
                entity.getType(),
                entity.getStatus(),
                entity.getDescription(),
                entity.getCreatedBy(),
                inScopeCount,
                targets,
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }

    private AssessmentDetailResponse toDetailResponse(Assessment entity) {
        List<ScopeDto> scopeDtos = entity.getScopes().stream()
                .map(s -> new ScopeDto(s.getId(), s.getTarget(), s.getTargetType(), s.getIsExcluded(), s.getDescription()))
                .toList();

        return new AssessmentDetailResponse(
                entity.getId(),
                entity.getName(),
                entity.getType(),
                entity.getStatus(),
                entity.getDescription(),
                entity.getCreatedBy(),
                scopeDtos,
                entity.getCreatedAt(),
                entity.getUpdatedAt()
        );
    }
}
