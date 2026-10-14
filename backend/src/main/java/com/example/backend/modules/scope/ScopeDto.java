package com.example.backend.modules.scope;


public record ScopeDto(
        Long id,
        String target,
        ScopeType targetType,
        Boolean isExcluded,
        String description
) {}
