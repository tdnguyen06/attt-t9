package com.example.backend.modules.mitre;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AttackPathDto {
    private String id;
    private String title;
    private String description;
    private String target;
    private String riskLevel; // CRITICAL, HIGH, MEDIUM
    private String impactSummary;

    @Builder.Default
    private List<AttackStepDto> steps = new ArrayList<>();

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AttackStepDto {
        private int stepNumber;
        private String tacticId;
        private String tacticName;
        private String techniqueId;
        private String techniqueName;
        private String actionDescription;
        private String vulnerabilityUsed;
        private String cveId;
        private String evidence;
        private String defenseRecommendation;
    }
}
