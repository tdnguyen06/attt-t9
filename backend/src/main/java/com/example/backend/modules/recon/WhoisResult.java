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
public class WhoisResult {
    private String query;
    private String registrar;
    private String creationDate;
    private String expiryDate;
    private String updatedDate;
    private String organization;
    private String country;
    @Builder.Default
    private List<String> nameServers = new ArrayList<>();
    private String rawWhois;
    private boolean success;
    private String errorMessage;
}
