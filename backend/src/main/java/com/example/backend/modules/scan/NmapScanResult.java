package com.example.backend.modules.scan;

import java.util.List;

public record NmapScanResult(
        String scanner,
        String args,
        String version,
        String scanTime,
        List<HostResult> hosts,
        int totalHostsUp,
        int totalOpenPorts
) {}
