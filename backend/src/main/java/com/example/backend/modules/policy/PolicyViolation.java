package com.example.backend.modules.policy;

public record PolicyViolation(
        String ruleName, // SCOPE_CHECK, ALLOWLIST_CHECK, APPROVAL_CHECK, RESOURCE_LIMIT_CHECK
        String severity, // HIGH, CRITICAL, MEDIUM
        String message
) {}
