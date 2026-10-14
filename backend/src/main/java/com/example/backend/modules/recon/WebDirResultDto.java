package com.example.backend.modules.recon;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebDirResultDto {
    private String path;
    private String url;
    private int statusCode;
    private String statusText;
    private long contentLength;
    private String redirectLocation;
    private boolean isSensitive;
    private String category; // ADMIN, BACKUP, CONFIG, API, AUTH, GENERAL
    private String riskLevel; // HIGH, MEDIUM, LOW, INFO
}
