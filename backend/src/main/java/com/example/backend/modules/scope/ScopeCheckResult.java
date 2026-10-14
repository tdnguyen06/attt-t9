package com.example.backend.modules.scope;

public record ScopeCheckResult(
        boolean inScope,
        String target,
        String matchedScope,
        String message
) {}
