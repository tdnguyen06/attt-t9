package com.example.backend.modules.reporting;


public interface ReportingService {

    AssessmentReportDto generateReport(Long assessmentId, GenerateReportRequest request);

    String exportReportAsMarkdown(Long reportId);

    AssessmentReportDto getReportByAssessmentId(Long assessmentId);

    AssessmentReportDto getReportById(Long id);
}
