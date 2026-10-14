package com.example.backend.modules.assessment;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

public record CreateAssessmentRequest(
        @NotBlank(message = "Tên phiên kiểm thử không được để trống")
        @Size(min = 3, max = 255, message = "Tên phải từ 3 đến 255 ký tự")
        String name,

        @NotNull(message = "Loại kiểm thử không được để trống (SERVER hoặc WEB)")
        AssessmentType type,

        String description,

        String createdBy,

        @NotEmpty(message = "Cần ít nhất một mục tiêu trong phạm vi")
        List<String> targets,

        List<String> excludedTargets // Danh sách loại trừ nếu có
) {}
