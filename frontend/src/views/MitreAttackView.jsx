import React, { useState, useEffect, useMemo } from 'react';
import apiClient from '../services/api';

export default function MitreAttackView({ setActiveTab, onAskAi }) {
  const [matrixData, setMatrixData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selectedTechnique, setSelectedTechnique] = useState(null);
  const [viewMode, setViewMode] = useState('matrix'); // 'matrix' | 'attack-paths' | 'registry'
  const [searchQuery, setSearchQuery] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [selectedPathIndex, setSelectedPathIndex] = useState(0);

  const fetchMatrix = async () => {
    try {
      setLoading(true);
      const res = await apiClient.get('/mitre/matrix');
      setMatrixData(res);
    } catch {
      setMatrixData(getFallbackMitreData());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMatrix();
  }, []);

  const filteredTactics = useMemo(() => {
    if (!matrixData?.tactics) return [];

    return matrixData.tactics.map((tactic) => {
      const filteredTechniques = (tactic.techniques || []).filter((tech) => {
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase().trim();
          const matchId = tech.id?.toLowerCase().includes(q);
          const matchName = tech.name?.toLowerCase().includes(q);
          const matchCve = (tech.sampleCves || []).some((c) => c.toLowerCase().includes(q));
          const matchFinding = (tech.findings || []).some((f) => f.title?.toLowerCase().includes(q) || f.cveId?.toLowerCase().includes(q));
          if (!matchId && !matchName && !matchCve && !matchFinding) return false;
        }

        if (filterSeverity === 'ACTIVE') return tech.activeInSystem;
        if (filterSeverity === 'CRITICAL') return tech.highestSeverity === 'CRITICAL';
        if (filterSeverity === 'HIGH') return tech.highestSeverity === 'CRITICAL' || tech.highestSeverity === 'HIGH';

        return true;
      });

      return {
        ...tactic,
        techniques: filteredTechniques,
      };
    });
  }, [matrixData, searchQuery, filterSeverity]);

  const handleAskAiAboutTechnique = (tech) => {
    if (!tech) return;
    const prompt = `Phân tích kỹ thuật MITRE ATT&CK: [${tech.id}] ${tech.name} (${tech.tacticName}).
Cơ chế khai thác: ${tech.exploitationMechanics || 'N/A'}.
${tech.findings?.length ? `Hệ thống ghi nhận ${tech.findings.length} lỗ hổng: ${tech.findings[0].title}.` : ''}
Hãy hướng dẫn: 1. Vector khai thác chính 2. Cách phát hiện (SIEM/EDR) 3. Biện pháp phòng vệ. Bắt đầu với BƯỚC 1!`;

    if (onAskAi) {
      onAskAi({ prompt, shortLabel: `${tech.id}: ${tech.name}` });
    } else if (setActiveTab) {
      sessionStorage.setItem('attt_pending_chat_prompt', JSON.stringify({ prompt, shortLabel: `${tech.id}: ${tech.name}` }));
      setActiveTab('chatbot');
    }
  };

  const handleExportMarkdown = () => {
    if (!matrixData) return;
    let md = `# BÁO CÁO MITRE ATT&CK\n*Thời gian:* ${new Date().toLocaleDateString('vi-VN')}\n\n`;
    md += `- **Độ phủ:** ${matrixData.matrixCoveragePercent}% (${matrixData.activeTechniquesDetected}/${matrixData.totalTechniquesMonitored})\n`;
    md += `- **Lỗ hổng:** ${matrixData.totalVulnerabilitiesMapped} (CRIT: ${matrixData.criticalFindingsCount}, HIGH: ${matrixData.highFindingsCount})\n\n`;

    matrixData.tactics.forEach((t) => {
      md += `### ${t.id} ${t.name}\n`;
      (t.techniques || []).forEach((tc) => {
        md += `- [${tc.id}] **${tc.name}** ${tc.activeInSystem ? `[🔴 ${tc.findingCount} lỗi]` : ''}\n`;
      });
      md += `\n`;
    });

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `MITRE_Report_${new Date().toISOString().slice(0, 10)}.md`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (sev) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL': return '#dc2626';
      case 'HIGH': return '#ea580c';
      case 'MEDIUM': return '#d97706';
      case 'LOW': return '#0284c7';
      default: return '#64748b';
    }
  };

  return (
    <div style={{ padding: '1rem', maxWidth: '1600px', margin: '0 auto' }}>
      {/* 1. Header & KPI */}
      <div
        style={{
          background: '#0f172a',
          border: '1px solid #1e293b',
          borderRadius: '10px',
          padding: '1.25rem',
          marginBottom: '1rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <i className="fa-solid fa-cubes-stacked" style={{ color: '#38bdf8', fontSize: '1.25rem' }}></i>
            <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#f8fafc', margin: 0 }}>
              Khung MITRE ATT&CK
            </h1>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              onClick={handleExportMarkdown}
              style={{
                background: 'rgba(56, 189, 248, 0.12)',
                border: '1px solid rgba(56, 189, 248, 0.4)',
                color: '#38bdf8',
                padding: '0.45rem 0.85rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
              }}
            >
              <i className="fa-solid fa-file-arrow-down"></i>
              Xuất Báo Cáo
            </button>
            <button
              type="button"
              onClick={fetchMatrix}
              style={{
                background: '#1e293b',
                border: '1px solid #334155',
                color: '#cbd5e1',
                padding: '0.45rem 0.75rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.35rem',
              }}
            >
              <i className={`fa-solid fa-rotate-right ${loading ? 'fa-spin' : ''}`}></i>
              Làm Mới
            </button>
          </div>
        </div>

        {/* 4 Chỉ số súc tích */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem' }}>
          <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.75rem' }}>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>ĐỘ PHỦ MA TRẬN</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.2rem' }}>
              {matrixData ? `${matrixData.matrixCoveragePercent}%` : '---'}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#64748b' }}>
              {matrixData?.activeTechniquesDetected || 0}/{matrixData?.totalTechniquesMonitored || 0} kỹ thuật
            </div>
          </div>

          <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.75rem' }}>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>KỸ THUẬT NGUY CƠ</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f43f5e', marginTop: '0.2rem' }}>
              {matrixData?.activeTechniquesDetected || 0}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#fca5a5' }}>Phát hiện lỗ hổng</div>
          </div>

          <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.75rem' }}>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>LỖ HỔNG ĐÃ GẮN</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#fb923c', marginTop: '0.2rem' }}>
              {matrixData?.totalVulnerabilitiesMapped || 0}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#64748b' }}>
              🔴 {matrixData?.criticalFindingsCount || 0} Crit • 🟠 {matrixData?.highFindingsCount || 0} High
            </div>
          </div>

          <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.75rem' }}>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>CHUỖI TẤN CÔNG</div>
            <div style={{ fontSize: '1.4rem', fontWeight: 800, color: '#c084fc', marginTop: '0.2rem' }}>
              {matrixData?.simulatedAttackPaths?.length || 2}
            </div>
            <div style={{ fontSize: '0.7rem', color: '#e9d5ff' }}>Kịch bản mô phỏng</div>
          </div>
        </div>
      </div>

      {/* 2. Mode Selector & Filters */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.75rem',
          marginBottom: '1rem',
          background: '#0f172a',
          padding: '0.6rem 0.85rem',
          borderRadius: '8px',
          border: '1px solid #1e293b',
        }}
      >
        <div style={{ display: 'flex', gap: '0.35rem', background: '#090e17', padding: '0.2rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
          <button
            type="button"
            onClick={() => setViewMode('matrix')}
            style={{
              background: viewMode === 'matrix' ? '#1e293b' : 'transparent',
              color: viewMode === 'matrix' ? '#38bdf8' : '#94a3b8',
              border: 'none',
              padding: '0.35rem 0.75rem',
              borderRadius: '4px',
              fontSize: '0.78rem',
              fontWeight: 700,
              cursor: 'pointer',
            }}
          >
            Ma Trận
          </button>
          <button
            type="button"
            onClick={() => setViewMode('attack-paths')}
            style={{
              background: viewMode === 'attack-paths' ? '#1e293b' : 'transparent',
              color: viewMode === 'attack-paths' ? '#38bdf8' : '#94a3b8',
              border: 'none',
              padding: '0.35rem 0.75rem',
              borderRadius: '4px',
              fontSize: '0.78rem',
              fontWeight: 700,
              cursor: 'pointer',
            }}
          >
            Chuỗi Tấn Công ({matrixData?.simulatedAttackPaths?.length || 2})
          </button>
          <button
            type="button"
            onClick={() => setViewMode('registry')}
            style={{
              background: viewMode === 'registry' ? '#1e293b' : 'transparent',
              color: viewMode === 'registry' ? '#38bdf8' : '#94a3b8',
              border: 'none',
              padding: '0.35rem 0.75rem',
              borderRadius: '4px',
              fontSize: '0.78rem',
              fontWeight: 700,
              cursor: 'pointer',
            }}
          >
            Tra Cứu
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
          <input
            type="text"
            placeholder="Tìm ID, CVE..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              background: '#090e17',
              border: '1px solid #334155',
              color: '#f8fafc',
              padding: '0.35rem 0.65rem',
              borderRadius: '5px',
              fontSize: '0.78rem',
              width: '180px',
              outline: 'none',
            }}
          />

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            style={{
              background: '#090e17',
              border: '1px solid #334155',
              color: '#f8fafc',
              padding: '0.35rem 0.65rem',
              borderRadius: '5px',
              fontSize: '0.78rem',
              outline: 'none',
              cursor: 'pointer',
            }}
          >
            <option value="ALL">Tất cả</option>
            <option value="ACTIVE">Có lỗ hổng</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High / Critical</option>
          </select>
        </div>
      </div>

      {/* 3. TAB 1: MA TRẬN GRID (Súc tích, không chữ thừa) */}
      {viewMode === 'matrix' && (
        <div style={{ overflowX: 'auto', paddingBottom: '0.75rem' }}>
          <div style={{ display: 'flex', gap: '0.65rem', minWidth: '1300px' }}>
            {filteredTactics.map((tactic) => (
              <div
                key={tactic.id}
                style={{
                  flex: '1 1 0',
                  minWidth: '200px',
                  background: '#0f172a',
                  border: '1px solid #1e293b',
                  borderRadius: '8px',
                  display: 'flex',
                  flexDirection: 'column',
                  overflow: 'hidden',
                }}
              >
                {/* Tactic Header */}
                <div
                  style={{
                    background: '#090e17',
                    padding: '0.65rem 0.75rem',
                    borderBottom: '2px solid ' + (tactic.color || '#38bdf8'),
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.7rem', fontWeight: 800, color: tactic.color || '#38bdf8' }}>
                      {tactic.id}
                    </span>
                    <span
                      style={{
                        fontSize: '0.68rem',
                        fontWeight: 700,
                        color: tactic.activeTechniquesCount > 0 ? '#f43f5e' : '#64748b',
                      }}
                    >
                      {tactic.activeTechniquesCount}/{tactic.techniques?.length || 0}
                    </span>
                  </div>
                  <div style={{ fontWeight: 700, fontSize: '0.82rem', color: '#f8fafc', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', marginTop: '0.15rem' }}>
                    {tactic.name}
                  </div>
                </div>

                {/* Technique Cards */}
                <div style={{ padding: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.45rem', flex: 1, minHeight: '340px', background: '#0a0f1d' }}>
                  {(!tactic.techniques || tactic.techniques.length === 0) ? (
                    <div style={{ textAlign: 'center', padding: '1.5rem 0.5rem', color: '#475569', fontSize: '0.72rem' }}>
                      Không có kỹ thuật
                    </div>
                  ) : (
                    tactic.techniques.map((tech) => {
                      const isActive = tech.activeInSystem;
                      const sevColor = getSeverityColor(tech.highestSeverity);

                      return (
                        <div
                          key={tech.id}
                          onClick={() => setSelectedTechnique(tech)}
                          style={{
                            background: isActive ? '#111c33' : '#0f172a',
                            border: isActive ? `1.5px solid ${sevColor}` : '1px solid #1e293b',
                            borderRadius: '5px',
                            padding: '0.55rem 0.65rem',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease',
                          }}
                        >
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                            <span style={{ fontSize: '0.68rem', fontWeight: 800, color: '#38bdf8' }}>
                              {tech.id}
                            </span>
                            {isActive && (
                              <span
                                style={{
                                  fontSize: '0.62rem',
                                  fontWeight: 800,
                                  color: '#fff',
                                  background: sevColor,
                                  padding: '0.08rem 0.35rem',
                                  borderRadius: '3px',
                                }}
                              >
                                {tech.findingCount} lỗi
                              </span>
                            )}
                          </div>

                          <div style={{ fontSize: '0.78rem', fontWeight: 600, color: '#f1f5f9', lineHeight: 1.3 }}>
                            {tech.name}
                          </div>

                          {tech.sampleCves && tech.sampleCves.length > 0 && (
                            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.2rem', marginTop: '0.35rem' }}>
                              {tech.sampleCves.slice(0, 2).map((cve, cveIdx) => (
                                <span
                                  key={cveIdx}
                                  style={{
                                    fontSize: '0.6rem',
                                    color: '#94a3b8',
                                    background: '#1e293b',
                                    padding: '0.05rem 0.3rem',
                                    borderRadius: '2px',
                                  }}
                                >
                                  {cve}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4. TAB 2: CHUỖI TẤN CÔNG (Timeline súc tích) */}
      {viewMode === 'attack-paths' && (
        <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: '1rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {(matrixData?.simulatedAttackPaths || []).map((path, pIdx) => (
              <div
                key={path.id || pIdx}
                onClick={() => setSelectedPathIndex(pIdx)}
                style={{
                  background: selectedPathIndex === pIdx ? '#13203c' : '#0f172a',
                  border: selectedPathIndex === pIdx ? '1.5px solid #38bdf8' : '1px solid #1e293b',
                  borderRadius: '6px',
                  padding: '0.75rem',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                  <span style={{ fontSize: '0.68rem', fontWeight: 800, color: '#38bdf8' }}>{path.id}</span>
                  <span style={{ fontSize: '0.62rem', fontWeight: 800, color: '#fff', background: '#dc2626', padding: '0.08rem 0.35rem', borderRadius: '2px' }}>
                    {path.riskLevel}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#f8fafc' }}>
                  {path.title}
                </div>
                <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>
                  <code>{path.target}</code>
                </div>
              </div>
            ))}
          </div>

          {matrixData?.simulatedAttackPaths?.[selectedPathIndex] && (
            <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
              {(() => {
                const currentPath = matrixData.simulatedAttackPaths[selectedPathIndex];
                return (
                  <>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem' }}>
                      <div>
                        <div style={{ fontSize: '1rem', fontWeight: 800, color: '#f8fafc' }}>{currentPath.title}</div>
                        <div style={{ fontSize: '0.75rem', color: '#fca5a5', marginTop: '0.2rem' }}>
                          ⚠️ Hậu quả: {currentPath.impactSummary}
                        </div>
                      </div>
                      <span style={{ fontSize: '0.7rem', color: '#38bdf8', background: '#090e17', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                        {currentPath.target}
                      </span>
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {(currentPath.steps || []).map((step, sIdx) => (
                        <div key={sIdx} style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                          <div
                            style={{
                              width: '24px',
                              height: '24px',
                              borderRadius: '50%',
                              background: '#38bdf8',
                              color: '#090e17',
                              fontWeight: 800,
                              fontSize: '0.75rem',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              flexShrink: 0,
                              marginTop: '0.2rem',
                            }}
                          >
                            {step.stepNumber}
                          </div>
                          <div style={{ flex: 1, background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.75rem' }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                              <span style={{ fontSize: '0.72rem', fontWeight: 800, color: '#38bdf8' }}>
                                [{step.techniqueId}] {step.techniqueName}
                              </span>
                              {step.cveId && (
                                <span style={{ fontSize: '0.68rem', color: '#f59e0b', background: '#1e293b', padding: '0.08rem 0.35rem', borderRadius: '3px' }}>
                                  {step.cveId}
                                </span>
                              )}
                            </div>
                            <div style={{ fontSize: '0.8rem', color: '#f1f5f9', fontWeight: 600 }}>
                              {step.actionDescription}
                            </div>
                            {step.evidence && (
                              <div style={{ background: '#020617', padding: '0.25rem 0.5rem', borderRadius: '3px', fontSize: '0.72rem', color: '#38bdf8', fontFamily: 'monospace', marginTop: '0.35rem' }}>
                                {step.evidence}
                              </div>
                            )}
                            <div style={{ fontSize: '0.72rem', color: '#34d399', marginTop: '0.35rem' }}>
                              Khắc phục: {step.defenseRecommendation}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                );
              })()}
            </div>
          )}
        </div>
      )}

      {/* 5. TAB 3: BẢNG TRA CỨU (Gọn gàng) */}
      {viewMode === 'registry' && (
        <div style={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px', overflow: 'hidden' }}>
          <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: '#090e17', borderBottom: '1px solid #1e293b', textAlign: 'left' }}>
                <th style={{ padding: '0.65rem 0.85rem', fontSize: '0.72rem', color: '#94a3b8' }}>MÃ KỸ THUẬT</th>
                <th style={{ padding: '0.65rem 0.85rem', fontSize: '0.72rem', color: '#94a3b8' }}>CHIẾN THUẬT</th>
                <th style={{ padding: '0.65rem 0.85rem', fontSize: '0.72rem', color: '#94a3b8' }}>CƠ CHẾ KHAI THÁC</th>
                <th style={{ padding: '0.65rem 0.85rem', fontSize: '0.72rem', color: '#94a3b8' }}>CVE</th>
                <th style={{ padding: '0.65rem 0.85rem', fontSize: '0.72rem', color: '#94a3b8' }}>TRẠNG THÁI</th>
                <th style={{ padding: '0.65rem 0.85rem', fontSize: '0.72rem', color: '#94a3b8', textAlign: 'right' }}>THAO TÁC</th>
              </tr>
            </thead>
            <tbody>
              {filteredTactics.flatMap((t) => t.techniques || []).map((tech) => {
                const isActive = tech.activeInSystem;
                const sevColor = getSeverityColor(tech.highestSeverity);

                return (
                  <tr key={tech.id} style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '0.65rem 0.85rem', verticalAlign: 'top' }}>
                      <div style={{ fontWeight: 800, color: '#38bdf8', fontSize: '0.8rem' }}>{tech.id}</div>
                      <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.78rem' }}>{tech.name}</div>
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', verticalAlign: 'top', fontSize: '0.75rem', color: '#cbd5e1' }}>
                      {tech.tacticName}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', verticalAlign: 'top', fontSize: '0.75rem', color: '#cbd5e1', maxWidth: '380px', lineHeight: 1.4 }}>
                      {tech.exploitationMechanics}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', verticalAlign: 'top' }}>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.2rem' }}>
                        {(tech.sampleCves || []).map((cve, cIdx) => (
                          <span key={cIdx} style={{ fontSize: '0.65rem', background: '#1e293b', color: '#38bdf8', padding: '0.05rem 0.3rem', borderRadius: '2px' }}>
                            {cve}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', verticalAlign: 'top' }}>
                      {isActive ? (
                        <span style={{ fontSize: '0.68rem', fontWeight: 800, color: '#fff', background: sevColor, padding: '0.12rem 0.45rem', borderRadius: '3px' }}>
                          {tech.findingCount} lỗ hổng
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.68rem', color: '#64748b' }}>-</span>
                      )}
                    </td>
                    <td style={{ padding: '0.65rem 0.85rem', verticalAlign: 'top', textAlign: 'right' }}>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.35rem' }}>
                        <button
                          type="button"
                          onClick={() => setSelectedTechnique(tech)}
                          style={{
                            background: '#1e293b',
                            border: '1px solid #334155',
                            color: '#e2e8f0',
                            fontSize: '0.72rem',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '3px',
                            cursor: 'pointer',
                          }}
                        >
                          Chi Tiết
                        </button>
                        <button
                          type="button"
                          onClick={() => handleAskAiAboutTechnique(tech)}
                          style={{
                            background: 'rgba(168, 85, 247, 0.15)',
                            border: '1px solid rgba(168, 85, 247, 0.4)',
                            color: '#c084fc',
                            fontSize: '0.72rem',
                            padding: '0.2rem 0.5rem',
                            borderRadius: '3px',
                            cursor: 'pointer',
                          }}
                        >
                          Hỏi AI
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* 6. MODAL CHI TIẾT (Gọn, súc tích) */}
      {selectedTechnique && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            background: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            zIndex: 1000,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '1rem',
          }}
          onClick={() => setSelectedTechnique(null)}
        >
          <div
            style={{
              background: '#0f172a',
              border: '1px solid #334155',
              borderRadius: '10px',
              maxWidth: '750px',
              width: '100%',
              maxHeight: '85vh',
              overflowY: 'auto',
              padding: '1.25rem',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontWeight: 800, color: '#38bdf8', background: 'rgba(56, 189, 248, 0.15)', padding: '0.12rem 0.45rem', borderRadius: '3px' }}>
                  {selectedTechnique.id}
                </span>
                <span style={{ fontSize: '1rem', fontWeight: 800, color: '#f8fafc' }}>
                  {selectedTechnique.name}
                </span>
                <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>
                  ({selectedTechnique.tacticName})
                </span>
              </div>

              <button
                type="button"
                onClick={() => setSelectedTechnique(null)}
                style={{ background: 'transparent', border: 'none', color: '#94a3b8', fontSize: '1.1rem', cursor: 'pointer' }}
              >
                <i className="fa-solid fa-xmark"></i>
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.75rem' }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#c084fc', marginBottom: '0.25rem' }}>CƠ CHẾ KHAI THÁC</div>
                <div style={{ color: '#e2e8f0', fontSize: '0.78rem', lineHeight: 1.45 }}>{selectedTechnique.exploitationMechanics}</div>
              </div>

              {selectedTechnique.findings?.length > 0 && (
                <div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#f43f5e', marginBottom: '0.4rem' }}>
                    LỖ HỔNG THỰC TẾ ({selectedTechnique.findings.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                    {selectedTechnique.findings.map((f, idx) => (
                      <div key={idx} style={{ background: '#090e17', borderLeft: `3px solid ${getSeverityColor(f.severity)}`, padding: '0.5rem 0.75rem', borderRadius: '0 4px 4px 0' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc' }}>
                          <span>[{f.severity}] {f.title}</span>
                          {f.cveId && <span style={{ color: '#38bdf8' }}>{f.cveId}</span>}
                        </div>
                        <div style={{ fontSize: '0.72rem', color: '#94a3b8', marginTop: '0.2rem' }}>
                          Mục tiêu: <code>{f.target}</code> {f.port && `:${f.port}`} | Khắc phục: {f.remediation}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <div style={{ background: '#090e17', padding: '0.65rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#fb923c', marginBottom: '0.2rem' }}>PHÁT HIỆN</div>
                  <div style={{ fontSize: '0.75rem', color: '#cbd5e1', lineHeight: 1.4 }}>{selectedTechnique.detectionGuidance}</div>
                </div>
                <div style={{ background: '#090e17', padding: '0.65rem', borderRadius: '6px' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#10b981', marginBottom: '0.2rem' }}>PHÒNG VỆ</div>
                  <div style={{ fontSize: '0.75rem', color: '#cbd5e1', lineHeight: 1.4 }}>{selectedTechnique.mitigationGuidance}</div>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.5rem' }}>
                <button
                  type="button"
                  onClick={() => {
                    const t = selectedTechnique;
                    setSelectedTechnique(null);
                    handleAskAiAboutTechnique(t);
                  }}
                  style={{
                    background: '#a855f7',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '5px',
                    padding: '0.45rem 0.9rem',
                    fontWeight: 700,
                    fontSize: '0.78rem',
                    cursor: 'pointer',
                  }}
                >
                  <i className="fa-solid fa-wand-magic-sparkles" style={{ marginRight: '0.35rem' }}></i>
                  Hỏi AI
                </button>
                <button
                  type="button"
                  onClick={() => setSelectedTechnique(null)}
                  style={{
                    background: '#1e293b',
                    color: '#94a3b8',
                    border: '1px solid #334155',
                    borderRadius: '5px',
                    padding: '0.45rem 0.85rem',
                    fontSize: '0.78rem',
                    cursor: 'pointer',
                  }}
                >
                  Đóng
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function getFallbackMitreData() {
  return {
    totalTactics: 10,
    totalTechniquesMonitored: 15,
    activeTechniquesDetected: 8,
    totalVulnerabilitiesMapped: 10,
    matrixCoveragePercent: 53.3,
    criticalFindingsCount: 3,
    highFindingsCount: 2,
    mediumFindingsCount: 4,
    lowFindingsCount: 1,
    tactics: [
      {
        id: 'TA0043',
        name: 'Reconnaissance',
        color: '#38bdf8',
        activeTechniquesCount: 1,
        techniques: [
          {
            id: 'T1592',
            name: 'Host Info Gathering',
            tacticName: 'Reconnaissance',
            exploitationMechanics: 'HTTP HEAD trích xuất Server header Nginx 1.22.1.',
            detectionGuidance: 'Giám sát lưu lượng quét web bất thường.',
            mitigationGuidance: 'Ẩn tiêu đề server_tokens off.',
            sampleCves: ['CWE-200'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'LOW',
            findings: [
              { id: 11, title: 'Lộ Server Header', severity: 'LOW', target: 'https://portal.vncert.vn', port: 443, cveId: 'CWE-200', remediation: 'server_tokens off;' },
            ],
          },
          {
            id: 'T1595',
            name: 'Active Scanning',
            tacticName: 'Reconnaissance',
            exploitationMechanics: 'Nmap SYN Scan cổng 80, 443, 6379, 5432.',
            detectionGuidance: 'NIDS phát hiện quét cổng.',
            mitigationGuidance: 'Firewall rate limiting.',
            sampleCves: ['Nmap Scan'],
            activeInSystem: false,
            findingCount: 0,
          },
        ],
      },
      {
        id: 'TA0001',
        name: 'Initial Access',
        color: '#f43f5e',
        activeTechniquesCount: 2,
        techniques: [
          {
            id: 'T1190',
            name: 'Exploit Public App',
            tacticName: 'Initial Access',
            exploitationMechanics: 'Payload HTTP POST khai thác Spring Boot Actuator hoặc Apache Path Traversal.',
            detectionGuidance: 'WAF log pattern JNDI, OGNL, %2e%2e.',
            mitigationGuidance: 'Vá lỗi kịp thời, cấu hình WAF.',
            sampleCves: ['CVE-2022-22965', 'CVE-2021-44228'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'CRITICAL',
            findings: [
              { id: 50, title: 'Lộ /actuator/env', severity: 'CRITICAL', target: 'https://api.vncert.vn', port: 443, cveId: 'CVE-2022-22965', remediation: 'management.endpoints.web.exposure.exclude=env' },
            ],
          },
          {
            id: 'T1189',
            name: 'Drive-by Compromise',
            tacticName: 'Initial Access',
            exploitationMechanics: 'Thiếu CSP dẫn đến chèn mã XSS.',
            detectionGuidance: 'Báo cáo CSP violation.',
            mitigationGuidance: 'Bật Content-Security-Policy.',
            sampleCves: ['CWE-1021'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'MEDIUM',
            findings: [
              { id: 10, title: 'Thiếu CSP Header', severity: 'MEDIUM', target: 'https://portal.vncert.vn', port: 443, cveId: 'CWE-1021', remediation: 'Bổ sung CSP header' },
            ],
          },
        ],
      },
      {
        id: 'TA0002',
        name: 'Execution',
        color: '#fb923c',
        activeTechniquesCount: 1,
        techniques: [
          {
            id: 'T1059',
            name: 'Command Interpreter',
            tacticName: 'Execution',
            exploitationMechanics: 'Thực thi lệnh shell qua Lua eval hoặc SpEL.',
            detectionGuidance: 'EDR phát hiện tiến trình con sinh từ web server.',
            mitigationGuidance: 'Chạy container non-root.',
            sampleCves: ['CVE-2022-0543'],
            activeInSystem: false,
            findingCount: 0,
          },
          {
            id: 'T1203',
            name: 'Client Execution',
            tacticName: 'Execution',
            exploitationMechanics: 'Thực thi mã phía Client qua thiếu CSP.',
            detectionGuidance: 'Giám sát lỗi CSP reporting.',
            mitigationGuidance: 'Thiết lập CSP và HttpOnly flag.',
            sampleCves: ['CWE-1021'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'MEDIUM',
          },
        ],
      },
      {
        id: 'TA0004',
        name: 'Privilege Escalation',
        color: '#ec4899',
        activeTechniquesCount: 1,
        techniques: [
          {
            id: 'T1068',
            name: 'Exploitation for Priv Esc',
            tacticName: 'Privilege Escalation',
            exploitationMechanics: 'Ghi authorized_keys qua Redis để đăng nhập root.',
            detectionGuidance: 'Giám sát file /root/.ssh/authorized_keys.',
            mitigationGuidance: 'Khóa quyền ghi root, chạy user redis.',
            sampleCves: ['CVE-2024-6387', 'CVE-2015-4335'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'CRITICAL',
            findings: [
              { id: 40, title: 'Redis mở không mật khẩu', severity: 'CRITICAL', target: '192.168.54.130', port: 6379, cveId: 'CVE-2015-4335', remediation: 'requirepass và bind 127.0.0.1' },
            ],
          },
        ],
      },
      {
        id: 'TA0006',
        name: 'Credential Access',
        color: '#6366f1',
        activeTechniquesCount: 2,
        techniques: [
          {
            id: 'T1040',
            name: 'Network Sniffing',
            tacticName: 'Credential Access',
            exploitationMechanics: 'Bắt gói tin HTTP clear-text cổng 80.',
            detectionGuidance: 'Phát hiện ARP Spoofing.',
            mitigationGuidance: 'Bắt buộc HTTPS & HSTS.',
            sampleCves: ['CWE-319'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'MEDIUM',
            findings: [
              { id: 20, title: 'HTTP quản trị không mã hóa', severity: 'MEDIUM', target: '192.168.54.1', port: 80, cveId: 'CWE-319', remediation: 'Chuyển hướng HTTPS' },
            ],
          },
          {
            id: 'T1552',
            name: 'Unsecured Credentials',
            tacticName: 'Credential Access',
            exploitationMechanics: 'Tải file backup.zip hoặc /actuator/env lấy secret key.',
            detectionGuidance: 'Giám sát request tới .zip, .sql, .env.',
            mitigationGuidance: 'Dùng Secret Vault, xóa file backup.',
            sampleCves: ['CWE-530'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'HIGH',
            findings: [
              { id: 30, title: 'Lộ file admin-backup.zip', severity: 'HIGH', target: 'https://shop.vncert.vn', port: 443, cveId: 'CWE-530', remediation: 'Xóa file zip' },
            ],
          },
        ],
      },
      {
        id: 'TA0008',
        name: 'Lateral Movement',
        color: '#f97316',
        activeTechniquesCount: 1,
        techniques: [
          {
            id: 'T1210',
            name: 'Exploit Remote Services',
            tacticName: 'Lateral Movement',
            exploitationMechanics: 'Kết nối Redis 6379 / SMB 445 mạng nội bộ.',
            detectionGuidance: 'Giám sát lưu lượng RPC/SMB giữa các máy trạm.',
            mitigationGuidance: 'Phân đoạn mạng, đặt mật khẩu mạnh.',
            sampleCves: ['CVE-2017-0144', 'CVE-2015-4335'],
            activeInSystem: true,
            findingCount: 1,
            highestSeverity: 'CRITICAL',
            findings: [
              { id: 40, title: 'Redis kết nối không xác thực', severity: 'CRITICAL', target: '192.168.54.130', port: 6379, cveId: 'CVE-2015-4335', remediation: 'requirepass và bind 127.0.0.1' },
            ],
          },
        ],
      },
      {
        id: 'TA0040',
        name: 'Impact',
        color: '#ef4444',
        activeTechniquesCount: 0,
        techniques: [
          {
            id: 'T1499',
            name: 'Endpoint DoS',
            tacticName: 'Impact',
            exploitationMechanics: 'Gói tin dị dạng gây cạn kiệt CPU/RAM.',
            detectionGuidance: 'Giám sát ngưỡng CPU/RAM.',
            mitigationGuidance: 'Cài đặt rate limiting.',
            sampleCves: ['CVE-2023-44487'],
            activeInSystem: false,
            findingCount: 0,
          },
        ],
      },
    ],
    simulatedAttackPaths: [
      {
        id: 'PATH-01',
        title: 'Web Portal -> Root Server',
        target: 'https://shop.vncert.vn & 192.168.54.130',
        riskLevel: 'CRITICAL',
        impactSummary: 'Chiếm quyền Root server DB và rò rỉ dữ liệu',
        steps: [
          { stepNumber: 1, techniqueId: 'T1592', techniqueName: 'Host Info Gathering', actionDescription: 'Quét web lộ phiên bản Server header', cveId: 'CWE-200', evidence: 'Server: nginx/1.22.1', defenseRecommendation: 'Tắt hiển thị phiên bản' },
          { stepNumber: 2, techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', actionDescription: 'Tải admin-backup.zip lấy chuỗi kết nối DB', cveId: 'CWE-530', evidence: 'GET /admin-backup.zip 200 OK', defenseRecommendation: 'Xóa tệp zip khỏi web root' },
          { stepNumber: 3, techniqueId: 'T1210', techniqueName: 'Exploit Remote Services', actionDescription: 'Kết nối cổng Redis 6379 không mật khẩu', cveId: 'CVE-2015-4335', evidence: 'PING -> PONG', defenseRecommendation: 'requirepass và bind 127.0.0.1' },
          { stepNumber: 4, techniqueId: 'T1068', techniqueName: 'Exploitation for Priv Esc', actionDescription: 'Ghi đè authorized_keys đăng nhập SSH root', cveId: 'T1068', evidence: 'ssh root@192.168.54.130 OK', defenseRecommendation: 'Khóa quyền ghi /root' },
        ],
      },
      {
        id: 'PATH-02',
        title: 'Spring Actuator -> Admin JWT',
        target: 'https://api.vncert.vn',
        riskLevel: 'CRITICAL',
        impactSummary: 'Bypass xác thực API quản trị',
        steps: [
          { stepNumber: 1, techniqueId: 'T1190', techniqueName: 'Exploit Public App', actionDescription: 'Truy cập endpoint /actuator/env công khai', cveId: 'CVE-2022-22965', evidence: 'GET /actuator/env 200 OK', defenseRecommendation: 'exclude=env trong properties' },
          { stepNumber: 2, techniqueId: 'T1552', techniqueName: 'Unsecured Credentials', actionDescription: 'Trích xuất jwt.secret từ biến môi trường', cveId: 'CWE-530', evidence: 'jwt.secret=***', defenseRecommendation: 'Dùng Secret Manager' },
          { stepNumber: 3, techniqueId: 'T1211', techniqueName: 'Defense Evasion', actionDescription: 'Tạo JWT giả mạo quyền ROLE_SUPERADMIN', cveId: 'T1211', evidence: 'Authorization: Bearer eyJ...', defenseRecommendation: 'Chuyển sang RS256' },
        ],
      },
    ],
  };
}
