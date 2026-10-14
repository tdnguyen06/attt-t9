package com.example.backend.modules.assessment;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/assessments")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AssessmentController {

    private final AssessmentService assessmentService;

    @PostMapping
    public ResponseEntity<AssessmentDetailResponse> createAssessment(
            @Valid @RequestBody CreateAssessmentRequest request
    ) {
        AssessmentDetailResponse response = assessmentService.create(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping
    public ResponseEntity<List<AssessmentResponse>> getAllAssessments() {
        return ResponseEntity.ok(assessmentService.getAll());
    }

    @GetMapping("/{id}")
    public ResponseEntity<AssessmentDetailResponse> getAssessmentById(@PathVariable Long id) {
        return ResponseEntity.ok(assessmentService.getById(id));
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<AssessmentDetailResponse> updateStatus(
            @PathVariable Long id,
            @Valid @RequestBody UpdateStatusRequest request
    ) {
        return ResponseEntity.ok(assessmentService.updateStatus(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAssessment(@PathVariable Long id) {
        assessmentService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
