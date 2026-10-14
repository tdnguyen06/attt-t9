package com.example.backend.modules.mitre;

import com.example.backend.modules.recon.VulnerabilityFindingDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/mitre")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class MitreController {

    private final MitreMappingService mitreMappingService;

    /**
     * Lấy toàn bộ Ma Trận MITRE ATT&CK cùng các lỗ hổng đã được ánh xạ từ hệ thống.
     */
    @GetMapping("/matrix")
    public ResponseEntity<MitreMatrixDto> getMatrix() {
        return ResponseEntity.ok(mitreMappingService.getMitreMatrix());
    }

    /**
     * Tra cứu chi tiết một kỹ thuật MITRE cụ thể.
     */
    @GetMapping("/techniques/{id}")
    public ResponseEntity<MitreTechniqueDto> getTechnique(@PathVariable String id) {
        return ResponseEntity.ok(mitreMappingService.getTechniqueDetail(id));
    }

    /**
     * Lấy danh sách chuỗi tấn công mô phỏng (Attack Paths).
     */
    @GetMapping("/attack-paths")
    public ResponseEntity<List<AttackPathDto>> getAttackPaths() {
        return ResponseEntity.ok(mitreMappingService.generateSimulatedAttackPaths());
    }

    /**
     * Ánh xạ động một lỗ hổng tùy ý vào MITRE ATT&CK.
     */
    @PostMapping("/map")
    public ResponseEntity<VulnerabilityFindingDto> mapVulnerability(@RequestBody VulnerabilityFindingDto dto) {
        mitreMappingService.mapFindingDto(dto);
        return ResponseEntity.ok(dto);
    }
}
