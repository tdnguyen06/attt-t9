import React, { useState, useEffect, useRef } from 'react';
import { apiClient, toastEmitter } from '../services/api';
import FormattedAiText from '../components/FormattedAiText';
import { extractDiscoveredVulnerabilities, buildBloodhoundContextString } from '../utils/vulnerabilityUtils';


export default function ChatbotAiView() {
  const [assessments, setAssessments] = useState([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState('');
  const [assessmentContext, setAssessmentContext] = useState(null);
  const [discoveredVulnerabilities, setDiscoveredVulnerabilities] = useState([]);

  const [sessionId, setSessionId] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: `### 🛡️ TRỢ LÝ AN TOÀN THÔNG TIN & KIỂM THỬ HỆ THỐNG
Chào mừng bạn! Tôi sẵn sàng phân tích lỗ hổng, hướng dẫn kiểm thử và đề xuất giải pháp an toàn hệ thống. Hãy gửi yêu cầu hoặc dán kết quả lệnh để tiếp tục.`,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);

  const [inputText, setInputText] = useState('');
  const [loading, setLoading] = useState(false);
  const [sessionSearch, setSessionSearch] = useState('');
  const [showHistoryDrawer, setShowHistoryDrawer] = useState(false);
  const [latestBloodhoundData, setLatestBloodhoundData] = useState(null);
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  const loadLatestBloodhound = async () => {
    try {
      const res = await apiClient.get('/bloodhound/history');
      if (Array.isArray(res) && res.length > 0) {
        const latest = res[0];
        setLatestBloodhoundData(latest);
        // Tự động bóc tách các lỗ hổng Active Directory mới nhất vào danh sách chủ đề kiểm thử AI
        const bhSummary = latest.summary || latest;
        const bhVulns = extractDiscoveredVulnerabilities({
          contextData: {
            bloodhoundData: {
              ...bhSummary,
              domain: latest.domain || bhSummary.domainName,
              host: latest.target || latest.host,
              aiExplanation: latest.aiExplanation || bhSummary.aiAnalysis
            }
          }
        });
        if (bhVulns && bhVulns.length > 0) {
          setDiscoveredVulnerabilities(prev => {
            const merged = [...bhVulns, ...prev];
            const seen = new Set();
            return merged.filter(item => {
              if (seen.has(item.title)) return false;
              seen.add(item.title);
              return true;
            });
          });
        }
      }
    } catch (e) {}
  };



  useEffect(() => {
    loadAssessments();
    loadSessions();
    loadLatestBloodhound();

    // Tự động gửi câu hỏi nếu được chuyển hướng từ màn hình Kiểm thử AD / màn hình khác
    try {
      const pendingStr = sessionStorage.getItem('attt_pending_chat_prompt');
      if (pendingStr) {
        sessionStorage.removeItem('attt_pending_chat_prompt');
        let promptToSend = pendingStr;
        let displayLabel = 'Phân tích dữ liệu Active Directory thực tế và hướng dẫn BƯỚC 1';
        try {
          const parsed = JSON.parse(pendingStr);
          if (parsed && parsed.prompt) {
            promptToSend = parsed.prompt;
            displayLabel = parsed.shortLabel || displayLabel;
          }
        } catch (e) {}

        setTimeout(() => {
          handleSend(promptToSend, displayLabel);
        }, 600);
      }
    } catch (e) {}
  }, []);

  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, loading]);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      const newHeight = Math.max(80, Math.min(textareaRef.current.scrollHeight, 260));
      textareaRef.current.style.height = `${newHeight}px`;
    }
  }, [inputText]);

  const loadAssessments = async () => {
    try {
      const res = await apiClient.get('/assessments');
      const list = Array.isArray(res) ? res : res?.data || [];
      setAssessments(list);
      if (list.length > 0) {
        // Ưu tiên chọn phiên kiểm thử Active Directory (ví dụ: Assessment 10) nếu có
        const adAssessment = list.find((a) =>
          (a.name || '').toLowerCase().includes('ad') ||
          (a.name || '').toLowerCase().includes('active directory')
        );
        const targetId = adAssessment ? adAssessment.id : list[0].id;
        handleSelectAssessment(targetId, list);
      } else {
        setDiscoveredVulnerabilities(extractDiscoveredVulnerabilities({}));
      }
    } catch (err) {
      console.warn('Không thể tải danh sách assessment');
      setDiscoveredVulnerabilities(extractDiscoveredVulnerabilities({}));
    }
  };

  const loadSessions = async () => {
    try {
      const data = await apiClient.get('/llm/sessions');
      if (Array.isArray(data)) {
        setSessions(data);
      }
    } catch (e) {
      console.error('Không thể tải danh sách session');
    }
  };

  const handleSelectAssessment = async (id, assessmentList = null) => {
    setSelectedAssessmentId(id);
    const currentList = assessmentList || assessments;
    if (!id) {
      setAssessmentContext(null);
      setDiscoveredVulnerabilities(extractDiscoveredVulnerabilities({}));
      return;
    }

    try {
      const [scans, report] = await Promise.all([
        apiClient.get(`/scans/assessment/${id}`).catch(() => []),
        apiClient.get(`/reports/assessment/${id}`).catch(() => null)
      ]);

      const found = currentList.find((a) => String(a.id) === String(id));
      const ctx = {
        assessment: found,
        scans: scans,
        report: report
      };
      setAssessmentContext(ctx);

      const vulns = extractDiscoveredVulnerabilities({
        report,
        scans,
        assessment: found
      });
      setDiscoveredVulnerabilities(vulns);

      // Đồng bộ dữ liệu BloodHound AD từ đợt kiểm thử vào localStorage
      if (Array.isArray(scans)) {
        scans.forEach((s) => {
          if (s?.parsedSummary) {
            try {
              const p = typeof s.parsedSummary === 'string' ? JSON.parse(s.parsedSummary) : s.parsedSummary;
              const bh = p?.recon?.bloodhoundAudit || p?.bloodhoundAudit;
              if (bh) {
                const authUser = bh.authenticatedUser || p?.recon?.authenticatedUser || '';
                localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
                  domain: bh.domainName || '',
                  host: s.target,
                  authenticatedUser: authUser,
                  hasValidCredentials: true,
                  summary: bh,
                  scannedAt: new Date().toISOString()
                }));
              }
            } catch (e) {}
          }
        });
      }

      if (!assessmentList) {
        toastEmitter.show('Đã nạp bối cảnh thực tế', `Đã nạp thành công ${vulns.length} lỗ hổng & điểm yếu thực tế từ "${found?.name || id}" vào AI!`, 'info');
      }
    } catch (err) {
      console.error('Lỗi khi tải bối cảnh assessment');
      setDiscoveredVulnerabilities(extractDiscoveredVulnerabilities({}));
    }
  };

  const handleSelectVulnerabilityTopic = (vuln) => {
    handleSend(vuln.prompt, vuln.title);
  };

  const buildContextString = () => {
    const lines = [];
    lines.push(`=== BỐI CẢNH KIỂM THỬ AN NINH MẠNG ===`);
    lines.push(`- Hướng dẫn kiểm thử và khắc phục lỗ hổng an ninh mạng.`);
    lines.push(`- Tự động nhận diện và cung cấp câu lệnh phù hợp với môi trường của người dùng (Linux / Windows CMD / PowerShell).`);
    lines.push(`- Mỗi bước đưa ra câu lệnh rõ ràng trong khối code block.`);
    lines.push(`- Giải thích mục đích câu lệnh ngắn gọn rồi chờ người dùng chạy và phản hồi kết quả.`);
    
    let hasAdAuditInContext = false;

    if (assessmentContext?.assessment) {
      const { assessment, scans, report } = assessmentContext;
      lines.push(`\n- Phiên đánh giá an ninh: ${assessment.name} (${assessment.type})`);
      lines.push(`- Danh sách mục tiêu: ${(assessment.targets || []).join(', ')}`);
      
      if (scans && scans.length > 0) {
        lines.push(`\n[KẾT QUẢ RÀ QUÉT MẠNG & DỊCH VỤ THỰC TẾ]:`);
        scans.forEach((s) => {
          lines.push(`- Mục tiêu: ${s.target} - Trạng thái: ${s.status}`);
          if (s.parsedSummary) {
            try {
              const p = typeof s.parsedSummary === 'string' ? JSON.parse(s.parsedSummary) : s.parsedSummary;
              if (p.hosts) {
                p.hosts.forEach((h) => {
                  const openPorts = (h.ports || []).map(pt => `${pt.portId}/${pt.protocol} (${pt.serviceName || 'Unknown'})`).join(', ');
                  lines.push(`  + IP ${h.ipAddress || h.ip}: ${openPorts || 'Không có cổng mở'}`);
                });
              }

              // Trích xuất BloodHound AD Audit
              const bh = p.recon?.bloodhoundAudit || p.bloodhoundAudit;
              if (bh) {
                hasAdAuditInContext = true;
                const authUser = bh.authenticatedUser || p?.recon?.authenticatedUser || '';
                let authPass = bh.password || '';
                try {
                  const cachedAd = JSON.parse(localStorage.getItem('attt_bloodhound_audit_data') || '{}');
                  if (!authPass && (cachedAd.authenticatedUser === authUser || !cachedAd.authenticatedUser)) {
                    authPass = cachedAd.password || '';
                  }
                } catch (e) {}
                lines.push('\n' + buildBloodhoundContextString(bh, bh.domainName || '', s.target, authUser, authPass));
              }

              // Trích xuất AI Explanation thực tế từ quét (Kịch bản kiểm thử, rủi ro an ninh, lời khuyên chuyên gia)
              if (p.aiExplanation) {
                const exp = p.aiExplanation;
                if (exp.expertAdvice) {
                  lines.push(`\n[ĐÁNH GIÁ CHI TIẾT TỪ CHUYÊN GIA AN NINH]:\n${exp.expertAdvice}`);
                }
                if (Array.isArray(exp.securityRisks) && exp.securityRisks.length > 0) {
                  lines.push(`\n[DANH SÁCH RỦI RO BẢO MẬT PHÁT HIỆN]:`);
                  exp.securityRisks.forEach(r => lines.push(`  * ${r}`));
                }
                if (Array.isArray(exp.recommendedPentestActions) && exp.recommendedPentestActions.length > 0) {
                  lines.push(`\n[KỊCH BẢN KIỂM THỬ THỰC NGHIỆM ĐỀ XUẤT (${exp.recommendedPentestActions.length} kịch bản)]:`);
                  exp.recommendedPentestActions.forEach(act => {
                    lines.push(`  * [Bước ${act.stepNumber}]: ${act.title} (Mục tiêu: ${act.target}) - Phương pháp: ${act.suggestedMethod || act.purpose}`);
                  });
                }
              }
            } catch (e) {}
          }
        });
      }
      if (report) {
        lines.push(`\n[BÁO CÁO TỔNG HỢP AN TOÀN]:`);
        if (report.executiveSummary) lines.push(`- Tóm tắt điều hành: ${report.executiveSummary}`);
        if (report.overallRiskScore) lines.push(`- Mức độ rủi ro tổng thể: ${report.overallRiskScore}`);
      }
    }

    // NẾU CHƯA CÓ TRONG ASSESSMENT, NẠP DỮ LIỆU TỪ BLOODHOUND AUDIT THỰC TẾ
    if (!hasAdAuditInContext) {
      if (latestBloodhoundData) {
        const bh = latestBloodhoundData.summary || latestBloodhoundData;
        const authUser = latestBloodhoundData.authenticatedUser || bh.authenticatedUser || '';
        let authPass = latestBloodhoundData.password || bh.password || '';
        try {
          const cachedAd = JSON.parse(localStorage.getItem('attt_bloodhound_audit_data') || '{}');
          if (!authPass && (cachedAd.authenticatedUser === authUser || !cachedAd.authenticatedUser)) {
            authPass = cachedAd.password || '';
          }
        } catch (e) {}
        const bhStr = buildBloodhoundContextString(bh, latestBloodhoundData.domain || bh.domainName || '', latestBloodhoundData.target || latestBloodhoundData.host || '', authUser, authPass);
        if (bhStr) lines.push('\n' + bhStr);
      } else {
        try {
          const cachedAdStr = typeof window !== 'undefined' ? localStorage.getItem('attt_bloodhound_audit_data') : null;
          if (cachedAdStr) {
            const parsedAd = JSON.parse(cachedAdStr);
            const bh = parsedAd.summary || parsedAd;
            const authUser = parsedAd.authenticatedUser || bh.authenticatedUser || '';
            const authPass = parsedAd.password || bh.password || '';
            const bhStr = buildBloodhoundContextString(bh, parsedAd.domain || bh.domainName || '', parsedAd.host || '', authUser, authPass);
            if (bhStr) lines.push('\n' + bhStr);
          }
        } catch (e) {}
      }
    }

    return lines.join('\n');
  };

  const handleSend = async (customPrompt = null, customDisplayText = null) => {
    const question = (customPrompt || inputText).trim();
    if (!question || loading) return;

    setInputText('');
    const userMsg = {
      role: 'user',
      text: customDisplayText || question,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setLoading(true);

    try {
      const payload = {
        sessionId: sessionId,
        message: question,
        contextInfo: buildContextString(),
        relatedTaskId: null
      };

      const res = await apiClient.post('/llm/chat', payload);
      if (res?.sessionId) {
        setSessionId(res.sessionId);
        loadSessions();
      }

      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          text: res?.reply || 'AI đã tiếp nhận câu hỏi của bạn.',
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } catch (err) {
      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          text: `⚠️ **Lỗi kết nối AI**: ${err?.message || 'Không thể kết nối đến máy chủ AI. Vui lòng kiểm tra lại cấu hình API key trong file .env.'}`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleSelectSession = async (sess) => {
    try {
      setLoading(true);
      setSessionId(sess.id);
      const msgList = await apiClient.get(`/llm/sessions/${sess.id}/messages`);
      if (Array.isArray(msgList) && msgList.length > 0) {
        setMessages(
          msgList.map((m) => ({
            role: m.role?.toLowerCase() === 'user' ? 'user' : 'assistant',
            text: m.content,
            time: m.createdAt ? new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''
          }))
        );
      }
      setShowHistoryDrawer(false);
    } catch (err) {
      console.error('Lỗi khi chuyển phiên');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSession = async (e, sessId) => {
    e.stopPropagation();
    if (!window.confirm('Bạn có chắc muốn xóa phiên hội thoại này khỏi cơ sở dữ liệu không?')) return;
    try {
      await apiClient.delete(`/llm/sessions/${sessId}`);
      toastEmitter.show('Đã xóa phiên chat', 'Đã xóa hội thoại thành công.', 'info');
      setSessions((prev) => prev.filter((s) => s.id !== sessId));
      if (sessionId === sessId) {
        handleNewChat();
      }
    } catch (err) {
      toastEmitter.show('Lỗi', 'Không thể xóa phiên hội thoại.', 'error');
    }
  };

  const handleNewChat = () => {
    setSessionId(null);
    setMessages([
      {
        role: 'assistant',
        text: `### 🛡️ TRỢ LÝ AN TOÀN THÔNG TIN & KIỂM THỬ HỆ THỐNG
Chào mừng bạn! Tôi sẵn sàng phân tích lỗ hổng, hướng dẫn kiểm thử và đề xuất giải pháp an toàn hệ thống. Hãy gửi yêu cầu hoặc dán kết quả lệnh để tiếp tục.`,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);
    setShowHistoryDrawer(false);
  };

  const filteredSessions = sessions.filter((s) =>
    (s.title || '').toLowerCase().includes(sessionSearch.toLowerCase())
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: 'calc(100vh - 76px)', minHeight: '560px', gap: '0.65rem' }}>
      
      {/* 1. Header Bar */}
      <div className="card-panel" style={{ padding: '0.6rem 1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.65rem', marginBottom: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'linear-gradient(135deg, #7c3aed, #0284c7)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: '1rem' }}>
            <i className="fa-solid fa-wand-magic-sparkles"></i>
          </div>
          <div>
            <div style={{ fontWeight: 800, color: '#f8fafc', fontSize: '1rem' }}>
              Trợ Lý AI
            </div>
            <div style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
              Tư vấn an toàn thông tin & hỗ trợ kiểm thử hệ thống
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
          <button className="btn btn-outline" style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }} onClick={handleNewChat}>
            <i className="fa-solid fa-plus"></i> Hội Thoại Mới
          </button>

          <button
            className={`btn ${showHistoryDrawer ? 'btn-purple' : 'btn-outline'}`}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            onClick={() => setShowHistoryDrawer(!showHistoryDrawer)}
          >
            <i className="fa-solid fa-clock-rotate-left"></i> Lịch Sử
          </button>
        </div>
      </div>

      {/* 2. Main Chat Area + Sidebar */}
      <div style={{ display: 'flex', flex: 1, gap: '0.75rem', minHeight: 0 }}>
        
        {/* Main Chat Box */}
        <div className="card-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 0, overflow: 'hidden', marginBottom: 0 }}>

          {/* Messages Scroll Area */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '0.85rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
            {messages.map((msg, idx) => {
              const isUser = msg.role === 'user';
              return (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    gap: '0.65rem',
                    alignSelf: isUser ? 'flex-end' : 'flex-start',
                    maxWidth: isUser ? '85%' : '96%',
                    flexDirection: isUser ? 'row-reverse' : 'row'
                  }}
                >
                  <div
                    style={{
                      width: '30px',
                      height: '30px',
                      borderRadius: '50%',
                      background: isUser ? '#0284c7' : 'linear-gradient(135deg, #7c3aed, #38bdf8)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      color: '#fff',
                      fontSize: '0.8rem',
                      flexShrink: 0
                    }}
                  >
                    <i className={isUser ? 'fa-solid fa-user' : 'fa-solid fa-shield-halved'}></i>
                  </div>

                  <div
                    style={{
                      background: isUser ? 'linear-gradient(135deg, #0369a1, #0284c7)' : '#090e17',
                      border: isUser ? 'none' : '1px solid #1e293b',
                      borderRadius: isUser ? '10px 2px 10px 10px' : '2px 10px 10px 10px',
                      padding: '0.65rem 0.95rem',
                      color: '#f8fafc',
                      fontSize: '0.85rem',
                      lineHeight: '1.5',
                      boxShadow: '0 2px 8px rgba(0,0,0,0.2)'
                    }}
                  >
                    {isUser ? (
                      <div style={{ whiteSpace: 'pre-wrap' }}>{msg.text}</div>
                    ) : (
                      <FormattedAiText content={msg.text} />
                    )}
                    <div style={{ fontSize: '0.68rem', color: isUser ? '#bae6fd' : '#64748b', marginTop: '0.3rem', textAlign: isUser ? 'right' : 'left' }}>
                      {msg.time}
                    </div>
                  </div>
                </div>
              );
            })}

            {loading && (
              <div style={{ display: 'flex', gap: '0.65rem', alignSelf: 'flex-start', maxWidth: '85%' }}>
                <div style={{ width: '30px', height: '30px', borderRadius: '50%', background: 'linear-gradient(135deg, #7c3aed, #38bdf8)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: '0.8rem', flexShrink: 0 }}>
                  <i className="fa-solid fa-spinner fa-spin"></i>
                </div>
                <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '2px 10px 10px 10px', padding: '0.65rem 0.95rem', color: '#94a3b8', fontSize: '0.82rem' }}>
                  <span style={{ color: '#c084fc', fontWeight: 600 }}>AI Security đang phân tích và soạn thảo phản hồi...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* KHUNG NHẬP LIỆU DUY NHẤT (GỘP CHUNG HỎI ĐÁP & GỬI KẾT QUẢ/BÁO LỖI) */}
          <div style={{ padding: '0.55rem 0.85rem', background: '#090e17', borderTop: '1px solid #1e293b', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            
            {/* Phím tắt hành động nhanh nếu vừa nhận câu trả lời */}
            {messages.length > 1 && messages[messages.length - 1].role === 'assistant' && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="btn btn-sm btn-outline"
                  style={{ fontSize: '0.72rem', padding: '0.2rem 0.6rem', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.4)' }}
                  onClick={() => handleSend('Tôi đã thực hiện xong bước trên và không có lỗi gì phát sinh. Hãy hướng dẫn tôi BƯỚC TIẾP THEO!', 'Đã xong bước trên, tiếp tục')}
                  disabled={loading}
                >
                  <i className="fa-solid fa-forward-step"></i> Đã xong bước trên ➔
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-outline"
                  style={{ fontSize: '0.72rem', padding: '0.2rem 0.6rem', color: '#f87171', borderColor: 'rgba(239, 68, 68, 0.3)' }}
                  onClick={() => {
                    setInputText(prev => prev ? prev : 'Tôi gặp lỗi khi thực hiện câu lệnh trên: \n');
                    textareaRef.current?.focus();
                  }}
                  disabled={loading}
                >
                  <i className="fa-solid fa-triangle-exclamation"></i> Báo lỗi bước trên
                </button>
              </div>
            )}

            <div
              style={{
                background: '#0c1322',
                border: '1px solid #334155',
                borderRadius: '8px',
                padding: '0.5rem 0.75rem',
                boxShadow: '0 2px 10px rgba(0, 0, 0, 0.35)',
              }}
            >
              <textarea
                ref={textareaRef}
                className="form-control"
                placeholder="Nhập câu hỏi, yêu cầu kiểm thử hoặc dán kết quả lệnh/thông báo lỗi từ terminal... (Enter để gửi, Shift+Enter xuống dòng)"
                value={inputText}
                onChange={(e) => setInputText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    if (inputText.trim() && !loading) {
                      handleSend();
                    }
                  }
                }}
                disabled={loading}
                rows={2}
                style={{
                  width: '100%',
                  fontSize: '0.88rem',
                  lineHeight: '1.45',
                  background: 'transparent',
                  border: 'none',
                  color: '#f8fafc',
                  padding: '0.25rem 0',
                  minHeight: '44px',
                  maxHeight: '160px',
                  resize: 'none',
                  outline: 'none',
                  boxShadow: 'none'
                }}
              />

              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '0.35rem', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ fontSize: '0.7rem', color: '#64748b' }}>
                  <kbd style={{ background: '#1e293b', padding: '1px 4px', borderRadius: '3px', color: '#cbd5e1' }}>Enter</kbd> gửi • <kbd style={{ background: '#1e293b', padding: '1px 4px', borderRadius: '3px', color: '#cbd5e1' }}>Shift+Enter</kbd> xuống dòng
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  {inputText.trim() && (
                    <button
                      type="button"
                      className="btn btn-sm btn-outline"
                      style={{ fontSize: '0.68rem', padding: '0.15rem 0.45rem', color: '#94a3b8' }}
                      onClick={() => setInputText('')}
                    >
                      Xóa
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn btn-purple"
                    disabled={!inputText.trim() || loading}
                    onClick={() => handleSend()}
                    style={{
                      fontSize: '0.8rem',
                      padding: '0.32rem 1rem',
                      fontWeight: 700,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.4rem'
                    }}
                  >
                    <i className={`fa-solid ${loading ? 'fa-spinner fa-spin' : 'fa-paper-plane'}`}></i>
                    <span>{loading ? 'Đang gửi...' : 'Gửi'}</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Sessions History Drawer */}
        {showHistoryDrawer && (
          <div className="card-panel" style={{ width: '280px', display: 'flex', flexDirection: 'column', padding: '1rem', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.9rem' }}>
                <i className="fa-solid fa-clock-rotate-left"></i> Lịch Sử Chat
              </span>
              <button className="btn btn-sm btn-outline" onClick={() => setShowHistoryDrawer(false)}>
                <i className="fa-solid fa-xmark"></i>
              </button>
            </div>

            <input
              type="text"
              className="form-control"
              placeholder="Tìm kiếm phiên..."
              value={sessionSearch}
              onChange={(e) => setSessionSearch(e.target.value)}
              style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem' }}
            />

            <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
              {filteredSessions.length > 0 ? (
                filteredSessions.map((s) => (
                  <div
                    key={s.id}
                    onClick={() => handleSelectSession(s)}
                    style={{
                      padding: '0.6rem 0.8rem',
                      background: sessionId === s.id ? 'rgba(124, 58, 237, 0.2)' : '#090e17',
                      border: sessionId === s.id ? '1px solid #a855f7' : '1px solid #1e293b',
                      borderRadius: '6px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: '0.5rem'
                    }}
                  >
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontWeight: 600, color: sessionId === s.id ? '#d8b4fe' : '#e2e8f0', fontSize: '0.8rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {s.title || 'Hội thoại không tên'}
                      </div>
                      <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>
                        {s.messageCount || 0} tin nhắn • {s.updatedAt ? new Date(s.updatedAt).toLocaleDateString('vi-VN') : ''}
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-sm btn-outline"
                      title="Xóa phiên chat"
                      style={{ padding: '0.2rem 0.4rem', fontSize: '0.7rem', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.3)', flexShrink: 0 }}
                      onClick={(e) => handleDeleteSession(e, s.id)}
                    >
                      <i className="fa-solid fa-trash-can"></i>
                    </button>
                  </div>
                ))
              ) : (
                <div style={{ fontSize: '0.78rem', color: '#64748b', textAlign: 'center', padding: '1rem 0' }}>
                  Chưa có lịch sử nào
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
