package com.example.backend.modules.scan;

import lombok.Getter;

@Getter
public enum ScanProfile {
    FULL_COMPREHENSIVE_SCAN("Quét toàn diện tất cả (Cổng + Dịch vụ + Phiên bản + Lỗ hổng)", "-Pn -sT -sV -sC --script-timeout 30s -T4"),
    DEFAULT_SCRIPTS("Quét toàn diện cơ bản", "-Pn -sT -sV -sC --script-timeout 30s -T4"),
    SERVICE_VERSION("Nhận diện phiên bản dịch vụ", "-Pn -sT -sV --version-intensity 3 -T4"),
    VULN_AUDIT("Quét rà soát lỗ hổng an toàn", "-Pn -sT -sV --script vuln --script-timeout 30s -T4"),
    QUICK_SCAN("Quét nhanh cổng thông dụng", "-Pn -sT -F -T4"),
    TOP_100_PORTS("Quét Top 100 cổng", "-Pn -sT --top-ports 100 -T4"),
    FULL_PORT_SCAN("Quét toàn bộ cổng TCP", "-Pn -sT -p- -T4");

    private final String description;
    private final String safeArguments;

    ScanProfile(String description, String safeArguments) {
        this.description = description;
        this.safeArguments = safeArguments;
    }
}
