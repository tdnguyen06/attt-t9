package com.example.backend.modules.reporting;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/reports")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ReportingController {

    private final ReportingService reportingService;

    @PostMapping("/generate/{assessmentId}")
    public ResponseEntity<AssessmentReportDto> generateReport(
            @PathVariable Long assessmentId,
            @RequestBody(required = false) GenerateReportRequest request
    ) {
        AssessmentReportDto report = reportingService.generateReport(assessmentId, request);
        return ResponseEntity.status(HttpStatus.CREATED).body(report);
    }

    @GetMapping("/assessment/{assessmentId}")
    public ResponseEntity<AssessmentReportDto> getReportByAssessment(@PathVariable Long assessmentId) {
        AssessmentReportDto report = reportingService.getReportByAssessmentId(assessmentId);
        return ResponseEntity.ok(report);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AssessmentReportDto> getReportById(@PathVariable Long id) {
        return ResponseEntity.ok(reportingService.getReportById(id));
    }

    @GetMapping("/{id}/export/markdown")
    public ResponseEntity<String> exportMarkdown(@PathVariable Long id) {
        String markdown = reportingService.exportReportAsMarkdown(id);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"assessment-report-" + id + ".md\"")
                .contentType(MediaType.TEXT_PLAIN)
                .body(markdown);
    }
}
