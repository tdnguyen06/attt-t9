package com.example.backend.modules.llm;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record LlmPlanSuggestion(
        @JsonAlias({"name", "planTitle"})
        String title,
        @JsonAlias({"overview", "description"})
        String summary,
        @JsonAlias({"risk", "risks"})
        String riskAssessment,
        @JsonAlias({"planSteps", "actions"})
        List<LlmStepSuggestion> steps
) {}

