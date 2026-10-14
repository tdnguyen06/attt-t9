package com.example.backend.modules.llm;

import com.example.backend.modules.scan.ScanService;
import com.example.backend.modules.scan.ScanTask;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/llm")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
@Slf4j
public class LlmController {

    private final LlmService llmService;
    private final ScanService scanService;

    @PostMapping("/explain-scan/{taskId}")
    public ResponseEntity<LlmScanExplanation> explainScanTask(@PathVariable Long taskId) {
        ScanTask task = scanService.getTaskById(taskId);
        LlmScanExplanation explanation = llmService.explainScanResult(
                task.getId(),
                task.getTarget(),
                task.getProfile() != null ? task.getProfile().name() : "QUICK_SCAN",
                task.getParsedSummary(),
                task.getRawXmlOutput()
        );
        return ResponseEntity.ok(explanation);
    }

    @PostMapping("/chat")
    public ResponseEntity<LlmChatResponse> chat(@RequestBody LlmChatRequest request) {
        LlmChatResponse response = llmService.chatWithAssistantSession(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<ChatSessionSummaryDto>> getSessions() {
        return ResponseEntity.ok(llmService.getAllSessions());
    }

    @GetMapping("/sessions/{sessionId}/messages")
    public ResponseEntity<List<ChatMessageDto>> getSessionMessages(@PathVariable Long sessionId) {
        return ResponseEntity.ok(llmService.getSessionMessages(sessionId));
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<Void> deleteSession(@PathVariable Long sessionId) {
        llmService.deleteSession(sessionId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/host-network-info")
    public ResponseEntity<HostNetworkInfoDto> getHostNetworkInfo() {
        return ResponseEntity.ok(llmService.getHostNetworkInfo());
    }
}

