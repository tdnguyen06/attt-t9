package com.example.backend.modules.recon;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class BloodhoundAuditSummaryDto {
    private String domainName;
    private int totalObjectsScanned;
    private int criticalRiskCount;
    private int highRiskCount;
    private int mediumRiskCount;
    
    @Builder.Default
    private List<BloodhoundFindingDto> highRiskFindings = new ArrayList<>();
    
    @Builder.Default
    private List<BloodhoundFindingDto> ownedAccountAttackPaths = new ArrayList<>();

    @Builder.Default
    private List<String> privilegedAdmins = new ArrayList<>();
    
    @Builder.Default
    private List<String> kerberoastableAccounts = new ArrayList<>();

    @Builder.Default
    private List<String> asrepRoastableAccounts = new ArrayList<>();

    private String authenticatedUser;
    
    @Builder.Default
    private Boolean hasValidCredentials = true;

    private String aiAnalysis;

    public BloodhoundAuditSummaryDto() {
        this.highRiskFindings = new ArrayList<>();
        this.ownedAccountAttackPaths = new ArrayList<>();
        this.privilegedAdmins = new ArrayList<>();
        this.kerberoastableAccounts = new ArrayList<>();
        this.asrepRoastableAccounts = new ArrayList<>();
        this.hasValidCredentials = true;
    }
}
