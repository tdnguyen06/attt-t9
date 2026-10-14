package com.example.backend.modules.policy;

import java.util.List;

public record PolicyEvaluationResult(
        boolean allowed,
        String target,
        String tool,
        String profile,
        List<PolicyViolation> violations,
        String summaryMessage
) {}
