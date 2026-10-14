import React from 'react';
import FormattedAiText from './FormattedAiText';

export default function ScanAiExplanationCard({ explanation, loading, onRefresh, onAskAi }) {
  if (loading) {
    return (
      <div className="ai-explanation-box loading">
        <div className="ai-box-header">
          <div className="ai-brand-badge">
            <span>AI Security Analyst</span>
          </div>
          <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>Đang phân tích dữ liệu chuyên sâu...</span>
        </div>
        <div style={{ textAlign: 'center', padding: '2rem 1rem', color: '#94a3b8' }}>
          <div style={{ fontWeight: 600, color: '#f1f5f9' }}>AI đang bóc tách kết quả quét và tổng hợp giải thích chi tiết...</div>
          <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '0.25rem' }}>Tự động phân loại rủi ro, phân tích ý nghĩa cổng và tạo khuyến nghị khắc phục thực tế.</div>
        </div>
      </div>
    );
  }

  if (!explanation) return null;

  const getRiskBadge = (risk) => {
    switch (risk?.toUpperCase()) {
      case 'CRITICAL':
        return <span className="pill-vuln critical">RẤT NGUY HIỂM</span>;
      case 'HIGH':
        return <span className="pill-vuln high">NGUY HIỂM CAO</span>;
      case 'MEDIUM':
        return <span className="pill-vuln med">TRUNG BÌNH</span>;
      case 'LOW':
        return <span className="pill-vuln low">THẤP</span>;
      default:
        return <span className="pill-vuln safe">AN TOÀN / BẢO VỆ TỐT</span>;
    }
  };

  return (
    <div className="ai-explanation-box">
      {/* Box Header */}
      <div className="ai-box-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div className="ai-brand-badge">
            <span>AI Security Analyst</span>
          </div>
          {getRiskBadge(explanation.riskLevel)}
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {onAskAi && (
            <button
              type="button"
              className="btn btn-purple"
              style={{ fontSize: '0.82rem', padding: '0.4rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}
              onClick={onAskAi}
            >
              <i className="fa-solid fa-wand-magic-sparkles"></i>
              <span>Khai Thác Lỗ Hổng Với AI</span>
            </button>
          )}
          {onRefresh && (
            <button className="btn btn-sm btn-outline" onClick={onRefresh} title="Phân tích lại">
              <i className="fa-solid fa-arrows-rotate"></i> Làm mới
            </button>
          )}
        </div>
      </div>

      {/* 1. Tóm tắt tổng quan dễ hiểu */}
      {explanation.summary && (
        <div className="ai-summary-card">
          <div className="ai-section-title">
            Ý Nghĩa Kết Quả Kiểm Thử:
          </div>
          <div className="ai-summary-text">
            {explanation.summary}
          </div>
          {explanation.targetAnalysis && (
            <div style={{ marginTop: '0.5rem', fontSize: '0.82rem', color: '#cbd5e1' }}>
              <strong style={{ color: '#94a3b8' }}>Tình trạng mục tiêu: </strong>
              {explanation.targetAnalysis}
            </div>
          )}
        </div>
      )}

      {/* 2. Danh sách cổng giải thích chi tiết */}
      {explanation.portsExplanation && explanation.portsExplanation.length > 0 && (
        <div style={{ marginTop: '1rem' }}>
          <div className="ai-section-title">
            Bóc Tách Ý Nghĩa & Rủi Ro Của Từng Cổng Dịch Vụ:
          </div>
          <div className="ai-port-grid">
            {explanation.portsExplanation.map((p, idx) => (
              <div key={idx} className="ai-port-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                  <span className="ai-port-badge">{p.port}</span>
                  <span className="ai-port-service">{p.service}</span>
                </div>
                <div style={{ fontSize: '0.82rem', color: '#cbd5e1', marginBottom: '0.4rem', lineHeight: '1.4' }}>
                  <strong>Ý nghĩa:</strong> {p.description}
                </div>
                {p.risk && (
                  <div style={{ fontSize: '0.78rem', color: '#fca5a5', background: 'rgba(239, 68, 68, 0.12)', padding: '0.35rem 0.55rem', borderRadius: '4px', border: '1px solid rgba(239, 68, 68, 0.25)' }}>
                    <strong>Rủi ro:</strong> {p.risk}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 2.5 CÂY QUYẾT ĐỊNH & ĐỀ XUẤT BƯỚC KIỂM THỬ TIẾP THEO (AI REASONING & NEXT ACTIONS) */}
      {explanation.nextPentestActions && explanation.nextPentestActions.length > 0 && (
        <div style={{ marginTop: '1.25rem', background: 'linear-gradient(135deg, rgba(88, 28, 135, 0.25) 0%, rgba(15, 23, 42, 0.8) 100%)', border: '1px solid rgba(168, 85, 247, 0.4)', borderRadius: '8px', padding: '1rem 1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <i className="fa-solid fa-crosshairs" style={{ color: '#c084fc', fontSize: '1.1rem' }}></i>
              <span style={{ fontWeight: 800, color: '#f3e8ff', fontSize: '0.95rem' }}>
                Đề Xuất Bước Kiểm Thử & Khai Thác Tiếp Theo:
              </span>
            </div>
            <span style={{ fontSize: '0.72rem', background: 'rgba(168, 85, 247, 0.2)', color: '#d8b4fe', padding: '0.15rem 0.5rem', borderRadius: '4px', border: '1px solid rgba(168, 85, 247, 0.35)', fontWeight: 700 }}>
              AI Reasoning Engine • {explanation.nextPentestActions.length} Bước
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {explanation.nextPentestActions.map((act, actIdx) => (
              <div key={actIdx} style={{ background: '#090e17', border: '1px solid #1e293b', borderLeft: '4px solid #a855f7', borderRadius: '0 6px 6px 0', padding: '0.85rem 1rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem', flexWrap: 'wrap', gap: '0.4rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span style={{ background: '#7c3aed', color: '#fff', fontSize: '0.7rem', fontWeight: 800, padding: '0.15rem 0.45rem', borderRadius: '3px' }}>
                      BƯỚC {act.stepNumber || actIdx + 1}
                    </span>
                    <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.88rem' }}>
                      {act.title}
                    </span>
                  </div>
                  {act.phase && (
                    <span style={{ fontSize: '0.72rem', fontWeight: 700, color: '#c084fc', background: 'rgba(168, 85, 247, 0.12)', padding: '0.15rem 0.45rem', borderRadius: '4px', border: '1px solid rgba(168, 85, 247, 0.3)' }}>
                      {act.phase}
                    </span>
                  )}
                </div>

                {act.suggestedMethod && (
                  <div style={{ background: '#050811', border: '1px solid #1e293b', borderRadius: '4px', padding: '0.4rem 0.65rem', marginBottom: '0.4rem', fontFamily: 'monospace', fontSize: '0.76rem', color: '#38bdf8', wordBreak: 'break-all', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <i className="fa-solid fa-terminal" style={{ color: '#64748b' }}></i>
                    <span><strong>Phương thức / Lệnh:</strong> {act.suggestedMethod}</span>
                  </div>
                )}

                <div style={{ fontSize: '0.78rem', color: '#cbd5e1', lineHeight: '1.45', marginBottom: '0.35rem' }}>
                  <strong style={{ color: '#94a3b8' }}>Mục đích:</strong> {act.purpose}
                </div>

                {act.expectedOutcome && (
                  <div style={{ fontSize: '0.76rem', color: '#34d399', background: 'rgba(16, 185, 129, 0.08)', padding: '0.35rem 0.6rem', borderRadius: '3px' }}>
                    <strong>Dấu hiệu xác nhận PoC thành công:</strong> {act.expectedOutcome}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}


      {/* 3. Mối nguy hại tiềm ẩn & Hướng dẫn khắc phục */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
        {/* Rủi ro */}
        {explanation.securityRisks && explanation.securityRisks.length > 0 && (
          <div className="ai-pane-box danger-pane">
            <div className="ai-pane-title">
              Mối Nguy Hại Tiềm Ẩn:
            </div>
            <ul className="ai-step-list">
              {explanation.securityRisks.map((risk, idx) => (
                <li key={idx} className="ai-risk-item">
                  <span>{risk}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Khắc phục */}
        {explanation.stepByStepGuide && explanation.stepByStepGuide.length > 0 && (
          <div className="ai-pane-box success-pane">
            <div className="ai-pane-title">
              Hướng Dẫn Khắc Phục Từng Bước:
            </div>
            <ul className="ai-step-list">
              {explanation.stepByStepGuide.map((step, idx) => (
                <li key={idx} className="ai-guide-item">
                  <span className="step-num">{idx + 1}</span>
                  <span>{step}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* 4. Lời khuyên chuyên gia */}
      {explanation.expertAdvice && (
        <div className="ai-advice-box">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontWeight: 600, color: '#fbbf24', fontSize: '0.85rem', marginBottom: '0.25rem' }}>
            Lời Khuyên Của Chuyên Gia An Toàn Thông Tin:
          </div>
          <div style={{ fontSize: '0.82rem', color: '#e2e8f0', lineHeight: 1.45 }}>
            {explanation.expertAdvice}
          </div>
        </div>
      )}
    </div>
  );
}
