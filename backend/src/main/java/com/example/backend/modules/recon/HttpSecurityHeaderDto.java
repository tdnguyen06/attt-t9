package com.example.backend.modules.recon;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class HttpSecurityHeaderDto {
    private String headerName;
    private String value;
    private boolean present;
    private String severity; // INFO, LOW, MEDIUM, HIGH
    private String description;
    private String recommendation;
}
