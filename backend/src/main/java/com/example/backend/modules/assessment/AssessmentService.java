package com.example.backend.modules.assessment;


import java.util.List;

public interface AssessmentService {

    AssessmentDetailResponse create(CreateAssessmentRequest request);

    List<AssessmentResponse> getAll();

    AssessmentDetailResponse getById(Long id);

    AssessmentDetailResponse updateStatus(Long id, UpdateStatusRequest request);

    void delete(Long id);

    Assessment findEntityById(Long id);
}
