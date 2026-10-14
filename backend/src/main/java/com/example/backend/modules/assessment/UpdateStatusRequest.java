package com.example.backend.modules.assessment;

import jakarta.validation.constraints.NotNull;

public record UpdateStatusRequest(
        @NotNull(message = "Trạng thái mới không được để trống")
        AssessmentStatus status,
        String reason
) {}
