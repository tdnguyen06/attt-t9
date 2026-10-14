package com.example.backend.modules.planning;

public interface PlanningService {

    AssessmentPlanDto generatePlanForAssessment(Long assessmentId);

    PlanStepDto approveStep(Long stepId, ApproveStepRequest request);

    PlanStepDto executeStep(Long stepId, String executedBy);

    AssessmentPlanDto approveAllSteps(Long assessmentId, String approvedBy);

    AssessmentPlanDto executeAllSteps(Long assessmentId, String executedBy);

    AssessmentPlanDto getPlanByAssessmentId(Long assessmentId);

    AssessmentPlanDto getPlanById(Long planId);
}
