package com.example.backend;

import com.example.backend.modules.audit.AuditLogService;
import com.example.backend.modules.llm.LlmProperties;
import com.example.backend.modules.llm.LlmScanExplanation;
import com.example.backend.modules.llm.LlmServiceImpl;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import static org.junit.jupiter.api.Assertions.*;

class LlmServiceFallbackTest {

    @Test
    void testThrowsExceptionWhenNotConfigured() {
        LlmProperties props = Mockito.mock(LlmProperties.class);
        Mockito.when(props.isConfigured()).thenReturn(false);
        AuditLogService auditLogService = new AuditLogService() {
            @Override
            public com.example.backend.modules.audit.AuditLog log(String requester, String action, String moduleName, String target, String inputData, com.example.backend.modules.audit.AuditDecision decision, String resultStatus, String errorMessage, String ipAddress) { return null; }
            @Override
            public java.util.List<com.example.backend.modules.audit.AuditLog> getRecentLogs() { return java.util.Collections.emptyList(); }
            @Override
            public java.util.List<com.example.backend.modules.audit.AuditLog> getLogsByModule(String moduleName) { return java.util.Collections.emptyList(); }
        };
        com.example.backend.modules.llm.ChatSessionRepository sessionRepo = Mockito.mock(com.example.backend.modules.llm.ChatSessionRepository.class);
        com.example.backend.modules.llm.ChatMessageRepository messageRepo = Mockito.mock(com.example.backend.modules.llm.ChatMessageRepository.class);

        LlmServiceImpl service = new LlmServiceImpl(props, auditLogService, sessionRepo, messageRepo);

        assertThrows(IllegalStateException.class, () -> {
            service.explainScanResult(
                    1L,
                    "127.0.0.1",
                    "QUICK_SCAN",
                    "{\"hosts\":[{\"ipAddress\":\"127.0.0.1\",\"ports\":[]}]}",
                    "<nmaprun></nmaprun>"
            );
        });
    }
}
