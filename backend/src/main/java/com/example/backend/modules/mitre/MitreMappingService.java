package com.example.backend.modules.mitre;

import com.example.backend.modules.recon.VulnerabilityFindingDto;
import com.example.backend.modules.reporting.VulnerabilityFinding;

import java.util.List;

public interface MitreMappingService {

    /**
     * Lấy toàn bộ Ma Trận MITRE ATT&CK cùng các lỗ hổng thực tế được ánh xạ.
     */
    MitreMatrixDto getMitreMatrix();

    /**
     * Tra cứu chi tiết một Technique cụ thể kèm bằng chứng và hướng dẫn phòng thủ.
     */
    MitreTechniqueDto getTechniqueDetail(String techniqueId);

    /**
     * Tự động ánh xạ một lỗ hổng (VulnerabilityFinding) vào MITRE ATT&CK Tactic & Technique.
     */
    void mapFinding(VulnerabilityFinding finding);

    /**
     * Tự động ánh xạ DTO lỗ hổng (VulnerabilityFindingDto).
     */
    void mapFindingDto(VulnerabilityFindingDto dto);

    /**
     * Sinh các chuỗi tấn công (Simulated Attack Paths) từ các lỗ hổng đã ghi nhận.
     */
    List<AttackPathDto> generateSimulatedAttackPaths();
}
