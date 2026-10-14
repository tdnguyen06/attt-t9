package com.example.backend.modules.recon;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class BloodhoundFindingDto {
    private String sourcePrincipal;
    private String targetObject;
    private String targetType; // User, Group, Computer, Domain
    private String relationshipType; // WriteDacl, GenericAll, DCSync, HasSPN, etc.
    private String riskLevel; // CRITICAL, HIGH, MEDIUM, LOW
    private String description;
    private String remediation;

    public String getSourcePrincipal() { return sourcePrincipal; }
    public void setSourcePrincipal(String sourcePrincipal) { this.sourcePrincipal = sourcePrincipal; }

    public String getTargetObject() { return targetObject; }
    public void setTargetObject(String targetObject) { this.targetObject = targetObject; }

    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }

    public String getRelationshipType() { return relationshipType; }
    public void setRelationshipType(String relationshipType) { this.relationshipType = relationshipType; }

    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getRemediation() { return remediation; }
    public void setRemediation(String remediation) { this.remediation = remediation; }
}
