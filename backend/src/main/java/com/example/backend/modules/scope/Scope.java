package com.example.backend.modules.scope;

import com.example.backend.modules.assessment.Assessment;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "scopes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Scope {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "assessment_id",
            nullable = false
    )
    @JsonBackReference
    private Assessment assessment;

    @Column(nullable = false, length = 500)
    private String target;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "target_type",
            nullable = false,
            length = 20
    )
    private ScopeType targetType;

    @Column(name = "is_excluded", nullable = false)
    @Builder.Default
    private Boolean isExcluded = false; // Blacklist / Phạm vi loại trừ

    @Column(name = "description")
    private String description;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (isExcluded == null) {
            isExcluded = false;
        }
    }
}
