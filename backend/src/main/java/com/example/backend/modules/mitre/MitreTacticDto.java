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
public class MitreTacticDto {
    private String id;               // e.g. TA0001
    private String name;             // e.g. Initial Access
    private String vietnameseName;   // e.g. Xâm nhập Ban đầu
    private int order;               // Thứ tự trong chuỗi Kill Chain (1..14)
    private String description;      // Mô tả mục tiêu chiến thuật
    private String icon;             // FontAwesome icon
    private String color;            // CSS color code
    @Builder.Default
    private List<MitreTechniqueDto> techniques = new ArrayList<>();
    
    // Thống kê động
    private int totalTechniques;
    private int activeTechniquesCount;
    private int criticalFindingsCount;
    private int highFindingsCount;
}
