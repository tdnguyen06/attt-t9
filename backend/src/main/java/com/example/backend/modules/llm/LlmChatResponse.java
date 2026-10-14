package com.example.backend.modules.llm;

public record LlmChatResponse(
        Long sessionId,
        String reply,
        String model
) {}
