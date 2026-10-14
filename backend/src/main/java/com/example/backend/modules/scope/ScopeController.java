package com.example.backend.modules.scope;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/scopes")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ScopeController {

    private final ScopeService scopeService;

    @GetMapping("/assessment/{assessmentId}")
    public ResponseEntity<List<ScopeDto>> getScopes(@PathVariable Long assessmentId) {
        return ResponseEntity.ok(scopeService.getScopesByAssessmentId(assessmentId));
    }

    @GetMapping("/verify")
    public ResponseEntity<ScopeCheckResult> verifyScope(
            @RequestParam Long assessmentId,
            @RequestParam String target
    ) {
        return ResponseEntity.ok(scopeService.verifyTargetInScope(assessmentId, target));
    }
}
