package com.example.backend.modules.audit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
    public AuditLog log(String requester, String action, String moduleName, String target,
                        String inputData, AuditDecision decision, String resultStatus,
                        String errorMessage, String ipAddress) {
        AuditLog auditLog = AuditLog.builder()
                .requester(requester != null ? requester : "system_operator")
                .action(action)
                .moduleName(moduleName)
                .target(target)
                .inputData(inputData)
                .decision(decision)
                .resultStatus(resultStatus)
                .errorMessage(errorMessage)
                .ipAddress(ipAddress != null ? ipAddress : "127.0.0.1")
                .createdAt(LocalDateTime.now())
                .build();

        log.info("[AUDIT] User: {} | Action: {} | Module: {} | Decision: {} | Status: {}",
                requester, action, moduleName, decision, resultStatus);

        return auditLogRepository.save(auditLog);
    }

    @Override
    @Transactional(readOnly = true)
    public List<AuditLog> getRecentLogs() {
        return auditLogRepository.findTop100ByOrderByCreatedAtDesc();
    }

    @Override
    @Transactional(readOnly = true)
    public List<AuditLog> getLogsByModule(String moduleName) {
        return auditLogRepository.findByModuleNameOrderByCreatedAtDesc(moduleName);
    }
}
