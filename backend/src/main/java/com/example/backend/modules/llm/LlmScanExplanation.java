package com.example.backend.modules.llm;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record LlmScanExplanation(
        @JsonAlias({"summary", "plainLanguageOverview", "overview", "executiveSummary", "generalSummary"})
        String summary,

        @JsonAlias({"targetAnalysis", "targetSummary", "target_analysis", "target"})
        String targetAnalysis,

        @JsonAlias({"riskLevel", "overallRiskLevel", "risk_level", "risk"})
        String riskLevel,

        @JsonAlias({"portsExplanation", "portExplanations", "ports_explanation", "ports", "services"})
        List<PortExplanation> portsExplanation,

        @JsonAlias({"nextPentestActions", "nextActions", "next_steps", "nextSteps", "recommendedActions", "pentestRoadmap"})
        List<NextPentestAction> nextPentestActions,

        @JsonAlias({"securityRisks", "potentialRisks", "security_risks", "risks", "vulnerabilities"})
        List<String> securityRisks,

        @JsonAlias({"stepByStepGuide", "steps", "step_by_step_guide", "guide", "remediationSteps", "recommendations"})
        List<String> stepByStepGuide,

        @JsonAlias({"expertAdvice", "advice", "expert_advice", "expertRecommendations", "conclusion"})
        String expertAdvice
) {
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record PortExplanation(
            @JsonAlias({"port", "portId", "port_id", "portNumber"})
            String port,

            @JsonAlias({"service", "serviceName", "service_name", "protocol"})
            String service,

            @JsonAlias({"description", "whatItMeans", "details", "desc", "analysis"})
            String description,

            @JsonAlias({"risk", "riskAndAdvice", "securityRisk", "impact"})
            String risk
    ) {}

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record NextPentestAction(
            @JsonAlias({"stepNumber", "step", "order"})
            Integer stepNumber,

            @JsonAlias({"title", "actionName", "action"})
            String title,

            @JsonAlias({"target", "service", "port"})
            String target,

            @JsonAlias({"phase", "testingPhase", "stage"})
            String phase, // THĂM DÒ (PROBE), KHAI THÁC THỬ NGHIỆM (POC), LEO THANG ĐẶC QUYỀN (PRIVILEGE), HƯỚNG DỰ PHÒNG (FALLBACK)

            @JsonAlias({"suggestedMethod", "technique", "command", "tool"})
            String suggestedMethod,

            @JsonAlias({"purpose", "rationale", "why"})
            String purpose,

            @JsonAlias({"expectedOutcome", "verification", "expectedSignal"})
            String expectedOutcome
    ) {}
}

