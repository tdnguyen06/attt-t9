package com.example.backend.modules.recon;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DnsRecordDto {
    private String type; // A, AAAA, CNAME, MX, TXT, NS, SOA
    private String value;
    private String raw;
}
