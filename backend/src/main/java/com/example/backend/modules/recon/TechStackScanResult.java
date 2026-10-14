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
public class TechStackScanResult {
    private String target;
    @Builder.Default
    private List<TechStackItemDto> technologies = new ArrayList<>();
    private String summary;
    private boolean success;
    private String errorMessage;
}
