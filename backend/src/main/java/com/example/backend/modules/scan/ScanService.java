package com.example.backend.modules.scan;

import com.example.backend.modules.planning.PlanStep;

import java.util.List;

public interface ScanService {

    ScanTask createScanTask(CreateScanTaskRequest request);

    ScanTask runScanForPlanStep(PlanStep step);

    void dispatchScanExecution(Long scanTaskId, Long stepId, String command, ScanProfile profile, String target, int timeoutSeconds);

    ScanTask completeScanWithXml(Long taskId, String xmlOutput);

    List<ScanTask> getTasksByAssessmentId(Long assessmentId);

    ScanTask getTaskById(Long taskId);

    String buildSafeNmapCommand(ScanProfile profile, String target);
}
