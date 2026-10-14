package com.example.backend.modules.planning;

public record ApproveStepRequest(
        String approvedBy,
        boolean approved,
        String comment
) {}
