package com.example.backend.modules.scan;

import java.util.List;

public record PortResult(
        int portId,
        String protocol, // tcp / udp
        String state, // open / filtered / closed
        String serviceName,
        String product,
        String version,
        String extraInfo,
        List<ScriptResult> scripts
) {}
