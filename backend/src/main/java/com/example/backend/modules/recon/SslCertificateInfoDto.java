package com.example.backend.modules.recon;

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
public class SslCertificateInfoDto {
    private String subject;
    private String issuer;
    private String validFrom;
    private String validTo;
    private long daysRemaining;
    private boolean expired;
    private String signatureAlgorithm;
    @Builder.Default
    private List<String> subjectAlternativeNames = new ArrayList<>();
}
