package com.example.backend.modules.scope;


import java.util.List;

public interface ScopeService {

    List<ScopeDto> getScopesByAssessmentId(Long assessmentId);

    ScopeCheckResult verifyTargetInScope(Long assessmentId, String target);
}
