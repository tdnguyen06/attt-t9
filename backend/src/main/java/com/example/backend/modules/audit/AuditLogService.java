package com.example.backend.modules.audit;


import java.util.List;

public interface AuditLogService {

    AuditLog log(String requester, String action, String moduleName, String target,
                 String inputData, AuditDecision decision, String resultStatus,
                 String errorMessage, String ipAddress);

    List<AuditLog> getRecentLogs();

    List<AuditLog> getLogsByModule(String moduleName);
}
