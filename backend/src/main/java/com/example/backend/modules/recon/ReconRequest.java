package com.example.backend.modules.recon;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReconRequest {
    @NotBlank(message = "Mục tiêu không được để trống")
    private String target; // Domain, IP hoặc URL
}
