package com.example.backend.modules.llm;

import java.util.List;

public record HostNetworkInfoDto(
        List<HostIpInterfaceDto> interfaces,
        String primaryVmHostIp,
        String primaryLanHostIp
) {
    public record HostIpInterfaceDto(
            String ipAddress,
            String interfaceName,
            String description
    ) {}
}
