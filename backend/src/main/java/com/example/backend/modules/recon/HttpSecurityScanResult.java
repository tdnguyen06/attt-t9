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
public class HttpSecurityScanResult {
    private String url;
    private Integer statusCode;
    private String serverBanner;
    private String poweredByBanner;
    private String grade; // A+, A, B, C, D, F
    private int score; // 0 - 100
    @Builder.Default
    private List<HttpSecurityHeaderDto> headers = new ArrayList<>();
    private SslCertificateInfoDto sslInfo;
    @Builder.Default
    private List<String> missingCriticalHeaders = new ArrayList<>();
    @Builder.Default
    private List<String> vulnerabilities = new ArrayList<>();
    private boolean success;
    private String errorMessage;
}
