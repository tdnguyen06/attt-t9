package com.example.backend.modules.scan;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record CreateScanTaskRequest(
        @NotNull(message = "Assessment ID không được để trống")
        Long assessmentId,

        @NotBlank(message = "Target không được để trống")
        String target,

        @NotNull(message = "Profile quét không được để trống")
        ScanProfile profile
) {}
