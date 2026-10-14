package com.example.backend.modules.llm;

import java.util.List;

public interface LlmService {

    LlmPlanSuggestion generateAssessmentPlan(String assessmentName, String type, List<String> targets);

    LlmAnalysisResult analyzeFindings(String assessmentName, String scanResultsSummary);

    LlmScanExplanation explainScanResult(Long taskId, String target, String profile, String parsedSummary, String rawOutput);

    LlmChatResponse chatWithAssistant(String message, String contextInfo);

    LlmChatResponse chatWithAssistantSession(LlmChatRequest request);

    List<ChatSessionSummaryDto> getAllSessions();

    List<ChatMessageDto> getSessionMessages(Long sessionId);

    void deleteSession(Long sessionId);

    HostNetworkInfoDto getHostNetworkInfo();
}

