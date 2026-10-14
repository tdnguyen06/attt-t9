package com.example.backend.modules.policy;

import com.example.backend.modules.planning.PlanStep;
import com.example.backend.modules.planning.PlanStepRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/policy")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class PolicyController {

    private final PolicyEngineService policyEngineService;
    private final SecurityPolicyConfig policyConfig;
    private final PlanStepRepository stepRepository;

    @GetMapping("/config")
    public ResponseEntity<SecurityPolicyConfig> getPolicyConfig() {
        return ResponseEntity.ok(policyConfig);
    }

    @PutMapping("/config")
    public ResponseEntity<SecurityPolicyConfig> updatePolicyConfig(@RequestBody SecurityPolicyConfig newConfig) {
        if (newConfig.getMaxTimeoutSeconds() > 0) {
            policyConfig.setMaxTimeoutSeconds(newConfig.getMaxTimeoutSeconds());
        }
        if (newConfig.getDefaultTimeoutSeconds() > 0) {
            policyConfig.setDefaultTimeoutSeconds(newConfig.getDefaultTimeoutSeconds());
        }
        if (newConfig.getMaxMemoryMb() > 0) {
            policyConfig.setMaxMemoryMb(newConfig.getMaxMemoryMb());
        }
        if (newConfig.getMaxOutputSizeKb() > 0) {
            policyConfig.setMaxOutputSizeKb(newConfig.getMaxOutputSizeKb());
        }
        if (newConfig.getMaxConcurrentTasks() > 0) {
            policyConfig.setMaxConcurrentTasks(newConfig.getMaxConcurrentTasks());
        }
        policyConfig.setEnforceApproval(newConfig.isEnforceApproval());
        return ResponseEntity.ok(policyConfig);
    }

    @PostMapping("/evaluate/step/{stepId}")
    public ResponseEntity<PolicyEvaluationResult> evaluateStep(
            @PathVariable Long stepId,
            @RequestParam(defaultValue = "180") int timeoutSeconds
    ) {
        PlanStep step = stepRepository.findById(stepId)
                .orElseThrow(() -> new IllegalArgumentException("Không tìm thấy bước với ID: " + stepId));

        PolicyEvaluationResult result = policyEngineService.evaluateStepExecution(
                step.getPlan().getAssessmentId(),
                step,
                timeoutSeconds
        );
        return ResponseEntity.ok(result);
    }
}
