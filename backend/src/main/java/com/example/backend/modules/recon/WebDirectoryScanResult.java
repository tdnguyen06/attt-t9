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
public class WebDirectoryScanResult {
    private String targetUrl;
    private int totalPathsTested;
    @Builder.Default
    private List<WebDirResultDto> discoveredPaths = new ArrayList<>();
    private int sensitiveCount;
    private long durationMs;
    private boolean success;
    private String errorMessage;
}
