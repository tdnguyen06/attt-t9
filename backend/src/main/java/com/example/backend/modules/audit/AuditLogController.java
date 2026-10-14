package com.example.backend.modules.audit;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/audit-logs")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class AuditLogController {

    private final AuditLogService auditLogService;

    @GetMapping
    public ResponseEntity<List<AuditLog>> getRecentAuditLogs() {
        return ResponseEntity.ok(auditLogService.getRecentLogs());
    }

    @GetMapping("/module/{moduleName}")
    public ResponseEntity<List<AuditLog>> getAuditLogsByModule(@PathVariable String moduleName) {
        return ResponseEntity.ok(auditLogService.getLogsByModule(moduleName));
    }
}
