package com.example.backend.modules.scan;

import java.util.List;

public record HostResult(
        String ipAddress,
        String hostName,
        String state, // up / down
        String osMatch,
        List<PortResult> ports
) {}
