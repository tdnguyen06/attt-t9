package com.example.backend.modules.mitre;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MitreFindingRefDto {
    private Long id;
    private String title;
    private String severity;
    private String target;
    private Integer port;
    private String serviceName;
    private String cveId;
    private String exploitationVector;
    private String remediation;
    private Boolean exploitAvailable;
    private Boolean cisaKev;
}
