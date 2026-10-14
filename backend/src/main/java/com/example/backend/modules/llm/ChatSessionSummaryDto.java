package com.example.backend.modules.llm;

import java.time.LocalDateTime;

public record ChatSessionSummaryDto(
        Long id,
        String title,
        Long relatedTaskId,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        int messageCount
) {
    public static ChatSessionSummaryDto fromEntity(ChatSession session) {
        return new ChatSessionSummaryDto(
                session.getId(),
                session.getTitle(),
                session.getRelatedTaskId(),
                session.getCreatedAt(),
                session.getUpdatedAt(),
                session.getMessages() != null ? session.getMessages().size() : 0
        );
    }
}
