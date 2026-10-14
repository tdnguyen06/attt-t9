package com.example.backend.modules.llm;

import java.time.LocalDateTime;

public record ChatMessageDto(
        Long id,
        String role,
        String content,
        LocalDateTime createdAt
) {
    public static ChatMessageDto fromEntity(ChatMessage entity) {
        return new ChatMessageDto(
                entity.getId(),
                entity.getRole(),
                entity.getContent(),
                entity.getCreatedAt()
        );
    }
}
