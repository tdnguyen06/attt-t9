package com.example.backend.modules.mitre;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class MitreTechniqueDto {
    private String id;                   // e.g. T1190
    private String name;                 // e.g. Exploit Public-Facing Application
    private String vietnameseName;       // e.g. Khai thác ứng dụng công khai
    private String tacticId;             // e.g. TA0001
    private String tacticName;           // e.g. Initial Access
    private String description;          // Mô tả kỹ thuật
    private String killChainStage;       // Vị trí trong Cyber Kill Chain
    private String exploitationMechanics;// Chi tiết cơ chế khai thác (Exploit Mechanics & Vectors)
    private String detectionGuidance;    // Hướng dẫn phát hiện (SIEM, EDR, Sigma)
    private String mitigationGuidance;   // Hướng dẫn khắc phục & phòng ngự
    private String url;                  // Link tham khảo MITRE ATT&CK chính thức

    @Builder.Default
    private List<String> sampleCves = new ArrayList<>();   // Các CVE tiêu biểu liên quan

    // Dữ liệu thực tế phát hiện trong hệ thống
    private boolean activeInSystem;      // true nếu hệ thống có lỗ hổng thuộc kỹ thuật này
    private int findingCount;            // Số lượng phát hiện thực tế
    private String highestSeverity;      // CRITICAL, HIGH, MEDIUM, LOW, INFO

    @Builder.Default
    private List<MitreFindingRefDto> findings = new ArrayList<>(); // Danh sách lỗ hổng thực tế
}
