package com.example.backend.modules.recon;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TechStackItemDto {
    private String name;
    private String category; // WEB_SERVER, FRONTEND_FRAMEWORK, BACKEND, CMS, CDN_WAF, ANALYTICS
    private String version;
    private String confidence; // HIGH, MEDIUM, LOW
    private String evidence;
    private String iconKey;
}
