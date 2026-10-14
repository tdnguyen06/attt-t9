package com.example.backend.modules.llm;

public record LlmChatRequest(
        Long sessionId,
        String message,
        String contextInfo,
        Long relatedTaskId
) {}
