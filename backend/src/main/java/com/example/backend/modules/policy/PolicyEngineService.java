package com.example.backend.modules.policy;

import com.example.backend.modules.planning.PlanStep;

public interface PolicyEngineService {

    PolicyEvaluationResult evaluateStepExecution(Long assessmentId, PlanStep step, int requestedTimeoutSeconds);
}
