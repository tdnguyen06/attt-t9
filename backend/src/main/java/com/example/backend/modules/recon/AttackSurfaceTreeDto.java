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
public class AttackSurfaceTreeDto {
    private String id;
    private String label;
    private String type; // ROOT, NETWORK_IP, PORT_SERVICE, TECH_STACK, VULNERABILITY, DIRECTORY
    private String status; // ONLINE, OPEN, VULNERABLE, SECURE, INFO
    private String details;
    @Builder.Default
    private List<AttackSurfaceTreeDto> children = new ArrayList<>();
}
