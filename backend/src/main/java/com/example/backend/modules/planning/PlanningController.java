package com.example.backend.modules.planning;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/plans")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class PlanningController {

    private final PlanningService planningService;

    @PostMapping("/generate/{assessmentId}")
    public ResponseEntity<AssessmentPlanDto> generatePlan(@PathVariable Long assessmentId) {
        AssessmentPlanDto plan = planningService.generatePlanForAssessment(assessmentId);
        return ResponseEntity.status(HttpStatus.CREATED).body(plan);
    }

    @GetMapping("/assessment/{assessmentId}")
    public ResponseEntity<AssessmentPlanDto> getPlanByAssessment(@PathVariable Long assessmentId) {
        AssessmentPlanDto plan = planningService.getPlanByAssessmentId(assessmentId);
        return ResponseEntity.ok(plan);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AssessmentPlanDto> getPlanById(@PathVariable Long id) {
        return ResponseEntity.ok(planningService.getPlanById(id));
    }

    @PostMapping("/steps/{stepId}/approve")
    public ResponseEntity<PlanStepDto> approveStep(
            @PathVariable Long stepId,
            @RequestBody ApproveStepRequest request
    ) {
        return ResponseEntity.ok(planningService.approveStep(stepId, request));
    }

    @PostMapping("/steps/{stepId}/execute")
    public ResponseEntity<PlanStepDto> executeStep(
            @PathVariable Long stepId,
            @RequestBody(required = false) Map<String, String> body
    ) {
        String executedBy = body != null ? body.get("executedBy") : "operator";
        return ResponseEntity.ok(planningService.executeStep(stepId, executedBy));
    }

    @PostMapping("/assessment/{assessmentId}/approve-all")
    public ResponseEntity<AssessmentPlanDto> approveAllSteps(
            @PathVariable Long assessmentId,
            @RequestBody(required = false) Map<String, String> body
    ) {
        String approvedBy = body != null ? body.get("approvedBy") : "Chuyên viên ATTT";
        return ResponseEntity.ok(planningService.approveAllSteps(assessmentId, approvedBy));
    }

    @PostMapping("/assessment/{assessmentId}/execute-all")
    public ResponseEntity<AssessmentPlanDto> executeAllSteps(
            @PathVariable Long assessmentId,
            @RequestBody(required = false) Map<String, String> body
    ) {
        String executedBy = body != null ? body.get("executedBy") : "Chuyên viên ATTT";
        return ResponseEntity.ok(planningService.executeAllSteps(assessmentId, executedBy));
    }
}
