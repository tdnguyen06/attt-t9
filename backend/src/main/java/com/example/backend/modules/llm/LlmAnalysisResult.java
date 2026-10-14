package com.example.backend.modules.llm;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record LlmAnalysisResult(
        String executiveSummary,
        String overallRiskScore, // CRITICAL, HIGH, MEDIUM, LOW
        List<String> keyVulnerabilities,
        List<String> attackScenarios,
        List<String> recommendations
) {}

