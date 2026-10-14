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
public class MitreMatrixDto {
    @Builder.Default
    private List<MitreTacticDto> tactics = new ArrayList<>();
    
    // Tổng quan ma trận
    private int totalTactics;
    private int totalTechniquesMonitored;
    private int activeTechniquesDetected;
    private int totalVulnerabilitiesMapped;
    private double matrixCoveragePercent;

    private int criticalFindingsCount;
    private int highFindingsCount;
    private int mediumFindingsCount;
    private int lowFindingsCount;

    @Builder.Default
    private List<AttackPathDto> simulatedAttackPaths = new ArrayList<>();
}
