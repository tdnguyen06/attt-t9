package com.example.backend.modules.scan;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/scans")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ScanController {

    private final ScanService scanService;

    @GetMapping("/profiles")
    public ResponseEntity<List<Map<String, String>>> getAvailableProfiles() {
        List<Map<String, String>> profiles = Arrays.stream(ScanProfile.values())
                .map(p -> Map.of(
                        "name", p.name(),
                        "description", p.getDescription(),
                        "safeArguments", p.getSafeArguments()
                ))
                .toList();
        return ResponseEntity.ok(profiles);
    }

    @PostMapping("/tasks")
    public ResponseEntity<ScanTask> createScanTask(@Valid @RequestBody CreateScanTaskRequest request) {
        ScanTask task = scanService.createScanTask(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(task);
    }

    @GetMapping("/assessment/{assessmentId}")
    public ResponseEntity<List<ScanTask>> getTasksByAssessment(@PathVariable Long assessmentId) {
        return ResponseEntity.ok(scanService.getTasksByAssessmentId(assessmentId));
    }

    @GetMapping("/tasks/{taskId}")
    public ResponseEntity<ScanTask> getTaskById(@PathVariable Long taskId) {
        return ResponseEntity.ok(scanService.getTaskById(taskId));
    }

    @PostMapping("/tasks/{taskId}/complete")
    public ResponseEntity<ScanTask> completeTaskWithXml(
            @PathVariable Long taskId,
            @RequestBody String xmlContent
    ) {
        return ResponseEntity.ok(scanService.completeScanWithXml(taskId, xmlContent));
    }
}
