package com.example.backend.modules.llm;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record LlmStepSuggestion(
        int stepNumber,
        @JsonAlias({"title", "stepName", "action"})
        String name,
        @JsonAlias({"command", "toolName"})
        String tool, // nmap, nikto, zap, curl
        @JsonAlias({"scanProfile"})
        String profile,
        @JsonAlias({"host", "ip", "url"})
        String target,
        @JsonAlias({"impact", "riskLevel"})
        String impactLevel, // LOW, MEDIUM, HIGH, CRITICAL
        @JsonAlias({"needApproval"})
        boolean requiresApproval,
        @JsonAlias({"details", "desc"})
        String description,
        @JsonAlias({"expectedOutput", "expectedResult", "outcome"})
        String expectedOutcome
) {}

