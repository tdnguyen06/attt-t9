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
public class DnsReconResult {
    private String domain;
    @Builder.Default
    private List<String> resolvedIps = new ArrayList<>();
    @Builder.Default
    private List<DnsRecordDto> records = new ArrayList<>();
    private String summary;
    private boolean success;
    private String errorMessage;
}
