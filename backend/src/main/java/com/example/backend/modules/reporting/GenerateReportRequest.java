package com.example.backend.modules.reporting;

public record GenerateReportRequest(
        String title,
        String generatedBy
) {}
