import React, { useState, useRef, useEffect } from 'react';
import { apiClient, toastEmitter } from '../services/api';
import FormattedAiText from './FormattedAiText';
import { extractDiscoveredVulnerabilities, buildBloodhoundContextString } from '../utils/vulnerabilityUtils';

function buildAnalysisContextString(contextData, networkInfo = null) {
  if (!contextData) return '';

  const vmHostIp = networkInfo?.primaryVmHostIp || '192.168.54.1';
  const lanHostIp = networkInfo?.primaryLanHostIp || '192.168.21.102';

  // Kiểm tra nghiêm ngặt: Mục tiêu có thực sự là Active Directory không
  const isAd = Boolean(
    contextData?.isAdAudit === true ||
    contextData?.assessment?.type === 'ACTIVE_DIRECTORY' ||
    (typeof contextData?.target === 'string' && (contextData.target.includes(':389') || contextData.target.includes(':636') || contextData.target.includes(':88') || contextData.target.toLowerCase().includes('ldap'))) ||
    (Array.isArray(contextData?.scans) && contextData.scans.some(s => s?.target && (s.target.includes(':389') || s.target.includes(':636') || s.target.includes(':88') || s.target.toLowerCase().includes('ldap')))) ||
    (Array.isArray(contextData?.scansSummary) && contextData.scansSummary.some(s => s?.target && (s.target.includes(':389') || s.target.includes(':636') || s.target.includes(':88') || s.target.toLowerCase().includes('ldap'))))
  );

  const netInfoBlock = `=== THÔNG TIN HẠ TẦNG KẾT NỐI & ĐỊA CHỈ IP MÁY CHỦ THỰC TẾ ===
- MÁY ẢO KALI LINUX (VMware VMnet8): IP MÁY CHỦ HOST LÀ \`${vmHostIp}\`
  * QUY TẮC BẮT BUỘC CHO AI: Khi người dùng thực thi lệnh từ máy ảo Kali Linux (bash terminal), BẠN BẮT BUỘC dùng IP \`${vmHostIp}\` cho mọi câu lệnh (ví dụ: http://${vmHostIp}:8088/). TUYỆT ĐỐI KHÔNG dùng 'localhost' vì trong Kali VM, localhost là chính máy Kali và cổng sẽ bị đóng (closed).
- MẠNG NỘI BỘ LAN / Wi-Fi: IP MÁY CHỦ LÀ \`${lanHostIp}\`
- MÁY HOST NỘI BỘ (WINDOWS): \`127.0.0.1\` hoặc \`localhost\`
=============================================================`;

  if (contextData.bloodhoundData && isAd) {
    return netInfoBlock + '\n\n' + buildBloodhoundContextString(contextData.bloodhoundData, contextData.domain, contextData.host);
  }

  if (typeof contextData === 'string') {
    return netInfoBlock + '\n\n' + contextData;
  }

  // 0. Trường hợp truyền vào Finding (Lỗ hổng cụ thể)
  if (contextData.finding) {
    const f = contextData.finding;
    const lines = [netInfoBlock];
    lines.push(`\n=== THÔNG TIN CHI TIẾT LỖ HỔNG & ĐIỂM YẾU BẢO MẬT ===`);
    lines.push(`- **Tên lỗ hổng**: ${f.title}`);
    lines.push(`- **Mức độ nghiêm trọng**: ${f.severity} - CVSS: ${f.cvssScore || 'N/A'}`);
    if (f.cveId) lines.push(`- **Mã CVE**: ${f.cveId}`);
    lines.push(`- **Mô tả chi tiết**: ${f.description}`);
    if (f.evidence) lines.push(`- **Bằng chứng kỹ thuật**: ${f.evidence}`);
    if (f.exploitationVector) lines.push(`- **Hướng & Kịch bản khai thác**: ${f.exploitationVector}`);
    if (f.remediation) lines.push(`- **Khuyến nghị khắc phục**: ${f.remediation}`);
    if (contextData.scanTask) {
      lines.push(`- **Mục tiêu**: ${contextData.scanTask.target}`);
    }
    lines.push(`==========================================================`);
    return lines.join('\n');
  }

  // 0.1 Trường hợp Pentest Action
  if (contextData.action) {
    const act = contextData.action;
    const lines = [netInfoBlock];
    lines.push(`\n=== ĐỀ XUẤT BƯỚC KIỂM THỬ & KHAI THÁC THỬ NGHIỆM ===`);
    lines.push(`- **Tiêu đề**: ${act.title}`);
    lines.push(`- **Giai đoạn**: ${act.phase || 'Kiểm thử thực nghiệm'}`);
    lines.push(`- **Mục tiêu**: ${act.target || 'Hạ tầng / Dịch vụ mục tiêu'}`);
    if (act.suggestedMethod) lines.push(`- **Phương thức / Lệnh gợi ý**: \`${act.suggestedMethod}\``);
    if (act.purpose) lines.push(`- **Mục đích**: ${act.purpose}`);
    if (act.expectedOutcome) lines.push(`- **Dấu hiệu PoC thành công**: ${act.expectedOutcome}`);
    lines.push(`==========================================================`);
    return lines.join('\n');
  }

  // 1. Tổng hợp toàn diện phiên đánh giá (Assessment) và Scan Tasks
  const lines = [netInfoBlock];

  if (contextData.assessment) {
    lines.push(`\n=== BỐI CẢNH PHIÊN ĐÁNH GIÁ AN TOÀN THÔNG TIN ===`);
    lines.push(`- **Tên phiên**: ${contextData.assessment.name || 'N/A'}`);
    lines.push(`- **Loại hình**: ${contextData.assessment.type || 'WEB'}`);
    lines.push(`- **Phạm vi mục tiêu**: ${contextData.assessment.targetScope || contextData.assessment.targets?.join(', ') || 'N/A'}`);
  }

  const scanList = [
    ...(Array.isArray(contextData.scans) ? contextData.scans : []),
    ...(Array.isArray(contextData.scansSummary) ? contextData.scansSummary : []),
    ...(contextData.scanTask ? [contextData.scanTask] : []),
  ];

  // Loại bỏ duplicate scans theo id / target
  const uniqueScans = [];
  const seenScanKeys = new Set();
  scanList.forEach(s => {
    if (s) {
      const key = s.id ? `id-${s.id}` : `target-${s.target}`;
      if (!seenScanKeys.has(key)) {
        seenScanKeys.add(key);
        uniqueScans.push(s);
      }
    }
  });

  if (uniqueScans.length > 0) {
    lines.push(`\n=== KẾT QUẢ RÀ QUÉT MỤC TIÊU, DỊCH VỤ & LỖ HỔNG THỰC TẾ ===`);
    uniqueScans.forEach((s) => {
      let summaryObj = s.summary || s.parsedSummary || (s.hosts || s.recon ? s : null);
      if (typeof summaryObj === 'string') {
        try {
          summaryObj = JSON.parse(summaryObj);
        } catch (e) {}
      }
      const scanTarget = s.target || 'Mục tiêu';
      lines.push(`\n[MỤC TIÊU: ${scanTarget}] (Cấu hình: ${s.profile || 'Scan'} - Trạng thái: ${s.status})`);

      // Dịch vụ và cổng mở
      if (summaryObj?.hosts && summaryObj.hosts.length > 0) {
        lines.push(`- Dịch Vụ & Cổng Mạng Mở:`);
        summaryObj.hosts.forEach((h) => {
          const hostIp = h.ipAddress || h.ip || scanTarget;
          const openPorts = (h.ports || [])
            .filter(p => String(p.state).toLowerCase() === 'open')
            .map(p => `${p.portId || p.port}/${p.protocol || 'tcp'} [${p.serviceName || 'Unknown'}${p.product ? ` - ${p.product}` : ''}${p.version ? ` v${p.version}` : ''}]`)
            .join('; ');
          lines.push(`  + Host ${hostIp}: ${openPorts || 'Không có cổng mở'}`);
        });
      }

      // Tech Stack
      const tech = summaryObj?.recon?.techStack?.technologies;
      if (Array.isArray(tech) && tech.length > 0) {
        lines.push(`- Công nghệ nhận diện được:`);
        tech.forEach(t => {
          lines.push(`  + ${t.name} (${t.category}): ${t.evidence || ''}`);
        });
      }

      // Lỗ hổng & CVEs thực tế
      const vulns = summaryObj?.recon?.vulnerabilityAudit?.findings;
      if (Array.isArray(vulns) && vulns.length > 0) {
        lines.push(`- LỖ HỔNG BẢO MẬT & CVEs PHÁT HIỆN TRÊN MỤC TIÊU:`);
        vulns.forEach((v) => {
          lines.push(`  * [${v.severity}] ${v.title}${v.cveId ? ` (Mã: ${v.cveId})` : ''} - CVSS: ${v.cvssScore || 'N/A'}`);
          if (v.evidence) lines.push(`    Bằng chứng: ${v.evidence}`);
          if (v.exploitationVector) lines.push(`    Hướng khai thác PoC: ${v.exploitationVector}`);
          if (v.remediation) lines.push(`    Khắc phục: ${v.remediation}`);
        });
      }

      // HTTP Security
      const httpSec = summaryObj?.recon?.httpSecurity;
      if (httpSec) {
        lines.push(`- Đánh giá an toàn HTTP: Điểm ${httpSec.score}/100 (Hạng ${httpSec.grade})`);
        if (httpSec.missingCriticalHeaders?.length > 0) {
          lines.push(`  + Thiếu Headers bảo mật: ${httpSec.missingCriticalHeaders.join(', ')}`);
        }
      }

      // AI Explanation
      const aiExp = summaryObj?.aiExplanation || s.aiExplanation;
      let expObj = aiExp;
      if (typeof expObj === 'string') {
        try { expObj = JSON.parse(expObj); } catch (e) {}
      }
      if (expObj && typeof expObj === 'object') {
        if (expObj.summary) lines.push(`- Tóm tắt rủi ro an toàn: ${expObj.summary}`);
        if (expObj.targetAnalysis) lines.push(`- Phân tích mục tiêu: ${expObj.targetAnalysis}`);
        if (Array.isArray(expObj.securityRisks) && expObj.securityRisks.length > 0) {
          lines.push(`- Mối nguy hại tiềm ẩn:`);
          expObj.securityRisks.slice(0, 5).forEach((rk, idx) => lines.push(`  ${idx + 1}. ${rk}`));
        }
        if (Array.isArray(expObj.nextPentestActions) && expObj.nextPentestActions.length > 0) {
          lines.push(`- Các hành động kiểm thử & PoC đề xuất:`);
          expObj.nextPentestActions.slice(0, 4).forEach((act) => {
            lines.push(`  * [${act.phase}] ${act.title}: \`${act.suggestedMethod}\``);
          });
        }
      }

      // CHỈ đính kèm BloodHound KHI mục tiêu THỰC SỰ là Active Directory
      if (isAd && summaryObj?.recon?.bloodhoundAudit) {
        const bh = summaryObj.recon.bloodhoundAudit;
        const bhStr = buildBloodhoundContextString(bh, bh.domainName || '', scanTarget, bh.authenticatedUser || '');
        if (bhStr) lines.push('\n' + bhStr);
      }
    });
  }

  // Báo cáo tổng hợp
  if (contextData.report) {
    lines.push(`\n=== BÁO CÁO TỔNG HỢP AN TOÀN HIỆN TẠI ===`);
    if (contextData.report.executiveSummary) lines.push(`- Tóm tắt: ${contextData.report.executiveSummary}`);
    if (contextData.report.overallRiskScore) lines.push(`- Mức rủi ro: ${contextData.report.overallRiskScore}`);
    if (contextData.report.recommendations) lines.push(`- Khuyến nghị: ${contextData.report.recommendations}`);
  }

  // QUY TẮC CÔ LẬP
  if (!isAd) {
    lines.push(`\n[QUY TẮC BẮT BUỘC VỀ PHẠM VI]: Mục tiêu kiểm thử này là WEB / SERVER / DỊCH VỤ MẠNG. TUYỆT ĐỐI KHÔNG nhắc đến, không hỏi và không đưa ra các công cụ hay tài khoản Active Directory (impacket, BloodHound, Kerberos, ldapsearch) vì hoàn toàn không liên quan đến mục tiêu Web này!`);
  }

  lines.push(`==========================================================`);
  return lines.join('\n');
}

export default function GroqAssistantModal({ isOpen, onClose, contextData, title, relatedTaskId }) {
  const [sessionId, setSessionId] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [showHistoryDrawer, setShowHistoryDrawer] = useState(false);
  const [showContextPreview, setShowContextPreview] = useState(false);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [sessionSearch, setSessionSearch] = useState('');
  const [copyFeedbackIndex, setCopyFeedbackIndex] = useState(null);
  const [discoveredVulnerabilities, setDiscoveredVulnerabilities] = useState([]);
  const [networkInfo, setNetworkInfo] = useState(null);

  const targetName = contextData?.scanTask?.target || contextData?.assessment?.targetScope || title || 'Toàn hệ thống';

  // Kiểm tra xem bối cảnh có phải là Active Directory không
  const isAdAudit = Boolean(
    contextData?.isAdAudit === true ||
    contextData?.assessment?.type === 'ACTIVE_DIRECTORY' ||
    (typeof contextData?.target === 'string' && (contextData.target.includes(':389') || contextData.target.includes(':636') || contextData.target.includes(':88') || contextData.target.toLowerCase().includes('ldap'))) ||
    (Array.isArray(contextData?.scans) && contextData.scans.some(s => s?.target && (s.target.includes(':389') || s.target.includes(':636') || s.target.includes(':88') || s.target.toLowerCase().includes('ldap')))) ||
    (Array.isArray(contextData?.scansSummary) && contextData.scansSummary.some(s => s?.target && (s.target.includes(':389') || s.target.includes(':636') || s.target.includes(':88') || s.target.toLowerCase().includes('ldap'))))
  );

  const vmHostIp = networkInfo?.primaryVmHostIp || '192.168.54.1';

  const getGreetingText = () => {
    if (isAdAudit) {
      return `Xin chào! Tôi là **Trợ lý An Ninh Mạng & Active Directory Pentest** 🛡️⚡.

Tôi đã nạp ma trận phân quyền Active Directory, cấu trúc miền và danh sách tài khoản của mục tiêu **\`${targetName}\`**.

Bạn cần hỗ trợ nội dung nào cho dự án kiểm thử này?
- 🏰 **Phân tích chuỗi rủi ro leo thang đặc quyền Active Directory (GenericAll, WriteDacl, AS-REP/Kerberoasting)**
- 🔍 **Đánh giá bề mặt tấn công tài khoản Domain và cấu hình Domain Controller**
- 🛡️ **Tư vấn giải pháp vá lỗi và Hardening chính sách miền**
- 📋 **Soạn thảo báo cáo an ninh mạng và khuyến nghị bảo mật**`;
    }

    return `Xin chào! Tôi là **Trợ lý Kiểm Thử Lỗ Hổng & An Toàn Ứng Dụng Web / Máy Chủ** 🌐⚡.

Tôi đã nạp đầy đủ kết quả rà quét dịch vụ mạng, thông tin banner, phiên bản máy chủ và các lỗ hổng bảo mật / CVEs của mục tiêu **\`${targetName}\`**.

🖥️ **Hạ tầng kết nối mục tiêu**:
- **Mục tiêu**: \`${targetName}\`
- **Địa chỉ IP máy chủ cho máy ảo Kali Linux (VMware VMnet8)**: \`${vmHostIp}\` (Cổng 8088 -> \`http://${vmHostIp}:8088/\`)
- **Địa chỉ máy chủ nội bộ (Windows)**: \`127.0.0.1:8088\` hoặc \`localhost:8088\`

Bạn muốn tôi hỗ trợ nội dung nào trước?
- 🎯 **Hướng dẫn khai thác thử nghiệm PoC lỗ hổng đã phát hiện (ví dụ: Path Traversal & RCE CVE-2021-41773 trên Apache 2.4.49)**
- 🔍 **Phân tích chi tiết rủi ro an toàn và các cổng dịch vụ mở**
- 🛡️ **Hướng dẫn vá lỗi, cập nhật phiên bản và cấu hình Hardening máy chủ**
- 📋 **Lập báo cáo đánh giá an toàn thông tin chuyên nghiệp**`;
  };

  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: getGreetingText(),
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [showStepResultBox, setShowStepResultBox] = useState(true);
  const [isStepResultCollapsed, setIsStepResultCollapsed] = useState(false);
  const [stepResultOutput, setStepResultOutput] = useState('');
  const [stepResultStatus, setStepResultStatus] = useState('SUCCESS'); // 'SUCCESS' | 'ERROR'
  const [showContextAttachment, setShowContextAttachment] = useState(false);
  const [attachedOutputLog, setAttachedOutputLog] = useState('');
  const [loading, setLoading] = useState(false);
  const messagesEndRef = useRef(null);
  const textareaRef = useRef(null);

  const handleSubmitStepResult = () => {
    const trimmed = stepResultOutput.trim();
    if (!trimmed || loading) return;

    const promptToSend = stepResultStatus === 'SUCCESS'
      ? `Dưới đây là kết quả thực hiện bước trên của tôi:\n\`\`\`\n${trimmed}\n\`\`\`\nHãy kiểm tra và thẩm định xem kết quả này đã ĐẠT YÊU CẦU chưa. Nếu ĐẠT, hãy xác nhận ngắn gọn và hướng dẫn tôi BƯỚC TIẾP THEO!`
      : `Tôi gặp lỗi sau khi thực hiện bước trên:\n\`\`\`\n${trimmed}\n\`\`\`\nHãy phân tích nguyên nhân lỗi và hướng dẫn tôi các câu lệnh khắc phục để hoàn thành bước này!`;

    setStepResultOutput('');
    handleSend(promptToSend, stepResultStatus === 'SUCCESS' ? 'Gửi kết quả bước thực thi' : 'Báo lỗi bước thực thi');
  };

  // Cuộn xuống cuối tin nhắn
  const scrollToBottom = () => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  // Load network info & danh sách sessions khi mở modal
  useEffect(() => {
    if (isOpen) {
      loadSessions();
      apiClient.get('/llm/host-network-info')
        .then(data => setNetworkInfo(data))
        .catch(() => {});
    }
  }, [isOpen]);

  // Reset và tự động gửi dữ liệu cho AI khi mở modal với contextData mới
  useEffect(() => {
    if (isOpen) {
      setSessionId(null);
      setMessages([
        {
          role: 'assistant',
          text: getGreetingText(),
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);

      if (contextData?.prompt || (typeof contextData === 'string' && contextData.includes('Active Directory'))) {
        const promptToSend = contextData?.prompt || contextData;
        const displayLabel = contextData?.shortLabel || 
                             contextData?.finding?.title || 
                             (typeof contextData === 'string' ? 'Phân tích dữ liệu kiểm thử và hướng dẫn BƯỚC 1' : 'Phân tích dữ liệu kiểm thử và hướng dẫn BƯỚC 1');
        setInputText('');
        handleSend(promptToSend, displayLabel);
      }
    }
  }, [isOpen, contextData]);


  // Nạp danh sách lỗ hổng đã phát hiện làm chủ đề trao đổi với AI
  useEffect(() => {
    if (!isOpen) return;

    let isSubscribed = true;
    const loadVulns = async () => {
      let vulns = extractDiscoveredVulnerabilities({
        contextData,
        report: contextData?.report,
        scans: contextData?.scans || contextData?.scansSummary,
        scanTask: contextData?.scanTask,
        finding: contextData?.finding,
        action: contextData?.action,
        explanation: contextData?.explanation,
        assessment: contextData?.assessment,
      });

      // Nếu contextData chỉ là chuỗi chung hoặc chưa có lỗ hổng cụ thể từ contextData, tải từ assessment gần nhất
      if ((!vulns || vulns.length <= 4) && (!contextData || typeof contextData === 'string')) {
        try {
          const res = await apiClient.get('/assessments');
          const list = Array.isArray(res) ? res : res?.data || [];
          if (list.length > 0) {
            const latestId = list[0].id;
            const [scans, report] = await Promise.all([
              apiClient.get(`/scans/assessment/${latestId}`).catch(() => []),
              apiClient.get(`/reports/assessment/${latestId}`).catch(() => null)
            ]);
            const liveVulns = extractDiscoveredVulnerabilities({
              report,
              scans,
              assessment: list[0]
            });
            if (liveVulns && liveVulns.length > 0 && isSubscribed) {
              vulns = liveVulns;
            }
          }
        } catch (e) {}
      }

      if (isSubscribed) {
        setDiscoveredVulnerabilities(vulns);
      }
    };

    loadVulns();
    return () => {
      isSubscribed = false;
    };
  }, [isOpen, contextData]);

  // Auto-resize textarea
  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      const newHeight = Math.max(76, Math.min(textareaRef.current.scrollHeight, 220));
      textareaRef.current.style.height = `${newHeight}px`;
    }
  }, [inputText]);

  const loadSessions = async () => {
    try {
      const data = await apiClient.get('/llm/sessions');
      if (Array.isArray(data)) {
        setSessions(data);
      }
    } catch (e) {
      console.error('Không thể tải lịch sử chat:', e);
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
            time: m.createdAt ? new Date(m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '',
          }))
        );
      } else {
        setMessages([
          {
            role: 'assistant',
            text: `Đã mở phiên chat: **${sess.title || 'Hội thoại'}**`,
            time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
          },
        ]);
      }
      setShowHistoryDrawer(false);
    } catch (err) {
      toastEmitter.show('Lỗi tải đoạn chat', 'Không thể nạp tin nhắn của phiên này.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSession = async (e, sessId) => {
    e.stopPropagation();
    if (!window.confirm('Bạn có chắc muốn xóa phiên hội thoại này không?')) return;
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
        text: initialGreeting,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      },
    ]);
    setShowHistoryDrawer(false);
  };

  const handleCopyMessage = (text, idx) => {
    navigator.clipboard.writeText(text);
    setCopyFeedbackIndex(idx);
    setTimeout(() => setCopyFeedbackIndex(null), 2000);
  };

  const handleSend = async (textToSend, customDisplayText = null) => {
    const question = textToSend || inputText;
    if (!question.trim() || loading) return;

    const displayQuestion = customDisplayText || question;
    const currentTime = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const newMessages = [...messages, { role: 'user', text: displayQuestion, time: currentTime }];
    setMessages(newMessages);
    setInputText('');
    setLoading(true);

    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
    }

    try {
      let formattedContext = buildAnalysisContextString(contextData, networkInfo);
      if (attachedOutputLog && attachedOutputLog.trim()) {
        formattedContext = (formattedContext ? formattedContext + '\n\n' : '') +
          `=== DỮ LIỆU ĐẦU RA / LOG HỆ THỐNG / KẾT QUẢ ĐÍNH KÈM ===\n${attachedOutputLog.trim()}\n======================================================`;
      }
      const oneLineRule = "\n\n[QUY TẮC BẮT BUỘC KHI HƯỚNG DẪN CODE]:\n- MÔI TRƯỜNG THỰC THI: KALI LINUX TERMINAL (BASH) HOẶC WINDOWS.\n- Tối ưu cho terminal của người dùng (Kali Linux hoặc Windows).\n- NẾU CẦN TOOL BÊN NGOÀI: BẮT BUỘC cung cấp câu lệnh cài đặt chính xác (sudo apt update && sudo apt install -y <package>).\n- Khối lệnh ghi rõ ```bash hoặc ```cmd.\n- Mỗi bước hướng dẫn CHỈ ĐƯỢC ĐƯA RA ĐÚNG 1 DÒNG CODE / 1 CÂU LỆNH THỰC THI DUY NHẤT trong khối code block.\n- TUYỆT ĐỐI KHÔNG ném cả một cục code hay script nhiều dòng cùng một lúc.\n- Giải thích ngắn gọn câu lệnh đó rồi dừng lại chờ người dùng chạy và gửi kết quả.";
      formattedContext = (formattedContext ? formattedContext : '') + oneLineRule;
      const taskId = relatedTaskId || contextData?.scanTask?.id || null;

      const res = await apiClient.post('/llm/chat', {
        sessionId: sessionId,
        message: question,
        contextInfo: formattedContext,
        relatedTaskId: taskId,
      });

      // Xóa log đính kèm sau khi gửi thành công nếu muốn
      setAttachedOutputLog('');
      setShowContextAttachment(false);

      if (res?.sessionId) {
        setSessionId(res.sessionId);
        // Cập nhật lại list session
        loadSessions();
      }

      let finalReply = res?.reply || 'Không nhận được phản hồi từ Trợ Lý AI. Vui lòng kiểm tra lại kết nối mạng hoặc máy chủ.';

      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          text: finalReply,
          model: res?.model || 'ai-model',
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } catch (err) {
      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          text: `⚠️ **Lỗi kết nối AI**: ${err?.message || 'Không thể kết nối đến máy chủ AI backend. Vui lòng kiểm tra lại dịch vụ.'}`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  if (!isOpen) return null;

  const filteredSessions = sessions.filter((s) =>
    (s.title || '').toLowerCase().includes(sessionSearch.toLowerCase())
  );

  return (
    <div className="cyber-modal-overlay">
      <div className={`cyber-ai-chat-window ${isFullScreen ? 'fullscreen' : ''}`}>

        {/* ================= 1. HEADER ================= */}
        <div className="cyber-chat-header">
          <div className="chat-header-brand">
            <div className="ai-avatar-glow">
              <i className="fa-solid fa-wand-magic-sparkles ai-pulse-icon"></i>
            </div>
            <div className="ai-title-block">
              <div className="ai-title-row">
                <span className="ai-main-title">Trợ Lý AI</span>
                <span className="cyber-pill-badge" style={{ background: 'rgba(56, 189, 248, 0.15)', borderColor: '#0284c7', color: '#38bdf8' }}>
                  <span className="dot-live"></span>
                  AI Security Pro
                </span>
              </div>
              <div className="ai-target-breadcrumb">
                <i className="fa-solid fa-shield-halved"></i>
                <span>Bối cảnh kiểm thử:</span>
                <span className="target-name-tag" title={targetName}>{targetName}</span>
              </div>
            </div>
          </div>

          <div className="chat-header-controls">
            {/* Nút xem dữ liệu bối cảnh */}
            {contextData && (
              <button
                type="button"
                className={`cyber-icon-btn ${showContextPreview ? 'active' : ''}`}
                onClick={() => setShowContextPreview(!showContextPreview)}
                title="Xem dữ liệu bối cảnh đang nạp cho AI"
              >
                <i className="fa-solid fa-database"></i>
                <span className="btn-label-desktop">Bối cảnh</span>
              </button>
            )}

            {/* Nút Lịch sử Chat */}
            <button
              type="button"
              className={`cyber-icon-btn ${showHistoryDrawer ? 'active' : ''}`}
              onClick={() => {
                setShowHistoryDrawer(!showHistoryDrawer);
                if (!showHistoryDrawer) loadSessions();
              }}
              title="Lịch sử các phiên hội thoại"
            >
              <i className="fa-solid fa-clock-rotate-left"></i>
              <span className="btn-label-desktop">Lịch sử</span>
              {sessions.length > 0 && <span className="badge-count">{sessions.length}</span>}
            </button>

            {/* Nút Chat mới */}
            <button
              type="button"
              className="cyber-icon-btn highlight"
              onClick={handleNewChat}
              title="Khởi tạo phiên trò chuyện mới"
            >
              <i className="fa-solid fa-plus"></i>
              <span className="btn-label-desktop">Chat mới</span>
            </button>

            {/* Nút Phóng to / Thu nhỏ */}
            <button
              type="button"
              className="cyber-icon-btn"
              onClick={() => setIsFullScreen(!isFullScreen)}
              title={isFullScreen ? 'Thu nhỏ giao diện' : 'Phóng to toàn màn hình'}
            >
              <i className={`fa-solid ${isFullScreen ? 'fa-compress' : 'fa-expand'}`}></i>
            </button>

            {/* Nút Đóng */}
            <button
              type="button"
              className="cyber-icon-btn close-btn"
              onClick={onClose}
              title="Đóng hộp thoại"
            >
              <i className="fa-solid fa-xmark"></i>
            </button>
          </div>
        </div>

        {/* ================= 2. BODY CONTAINER ================= */}
        <div className="cyber-chat-body-container">

          {/* 2.1 DRAWER LỊCH SỬ CHAT (Collapsible) */}
          {showHistoryDrawer && (
            <aside className="chat-sessions-drawer">
              <div className="drawer-header">
                <div className="drawer-title">
                  <i className="fa-solid fa-boxes-stacked"></i>
                  <span>Lịch Sử Hội Thoại</span>
                </div>
                <button
                  type="button"
                  className="drawer-close"
                  onClick={() => setShowHistoryDrawer(false)}
                >
                  <i className="fa-solid fa-chevron-left"></i>
                </button>
              </div>

              <div className="drawer-search">
                <i className="fa-solid fa-magnifying-glass"></i>
                <input
                  type="text"
                  placeholder="Tìm kiếm đoạn chat..."
                  value={sessionSearch}
                  onChange={(e) => setSessionSearch(e.target.value)}
                />
              </div>

              <div className="drawer-session-list">
                {filteredSessions.length === 0 ? (
                  <div className="drawer-empty-state">
                    <i className="fa-regular fa-comment-dots"></i>
                    <p>Chưa có phiên hội thoại nào được lưu.</p>
                  </div>
                ) : (
                  filteredSessions.map((s) => (
                    <div
                      key={s.id}
                      className={`session-card-item ${sessionId === s.id ? 'active' : ''}`}
                      onClick={() => handleSelectSession(s)}
                    >
                      <div className="session-card-content">
                        <div className="session-card-title">
                          <i className="fa-regular fa-message"></i>
                          <span>{s.title || `Hội thoại #${s.id}`}</span>
                        </div>
                        <div className="session-card-meta">
                          <span>{s.messageCount || 0} tin nhắn</span>
                          {s.updatedAt && (
                            <span>• {new Date(s.updatedAt).toLocaleDateString('vi-VN')}</span>
                          )}
                        </div>
                      </div>
                      <button
                        type="button"
                        className="session-delete-btn"
                        onClick={(e) => handleDeleteSession(e, s.id)}
                        title="Xóa phiên chat này"
                      >
                        <i className="fa-solid fa-trash-can"></i>
                      </button>
                    </div>
                  ))
                )}
              </div>
            </aside>
          )}

          {/* 2.2 DRAWER XEM TRƯỚC BỐI CẢNH (Context Inspector) */}
          {showContextPreview && (
            <aside className="chat-context-drawer">
              <div className="drawer-header">
                <div className="drawer-title">
                  <i className="fa-solid fa-file-shield"></i>
                  <span>Dữ Liệu Bối Cảnh Được Nạp</span>
                </div>
                <button
                  type="button"
                  className="drawer-close"
                  onClick={() => setShowContextPreview(false)}
                >
                  <i className="fa-solid fa-xmark"></i>
                </button>
              </div>
              <div className="drawer-context-content">
                <pre className="context-code-view">
                  {buildAnalysisContextString(contextData, networkInfo)}
                </pre>
              </div>
            </aside>
          )}

          {/* 2.3 KHUNG HỘI THOẠI CHÍNH */}
          <div className="chat-main-area">

            {/* Banner hiển thị IP kết nối máy chủ cho máy ảo Kali Linux & LAN */}
            {networkInfo && (
              <div style={{
                background: 'linear-gradient(90deg, rgba(30, 58, 138, 0.4), rgba(15, 23, 42, 0.6))',
                borderBottom: '1px solid rgba(59, 130, 246, 0.3)',
                padding: '0.55rem 1.25rem',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '0.5rem',
                fontSize: '0.8rem',
                color: '#cbd5e1'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <i className="fa-solid fa-network-wired" style={{ color: '#38bdf8' }}></i>
                  <span><strong>IP máy host (Dành cho máy ảo Kali Linux):</strong> <code style={{ color: '#67e8f9', background: 'rgba(0,0,0,0.4)', padding: '0.15rem 0.45rem', borderRadius: '4px', fontWeight: 700 }}>{networkInfo.primaryVmHostIp || '192.168.54.1'}</code></span>
                  {networkInfo.primaryLanHostIp && (
                    <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>| LAN: <code>{networkInfo.primaryLanHostIp}</code></span>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <button
                    type="button"
                    style={{ background: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.35)', color: '#38bdf8', borderRadius: '4px', padding: '0.2rem 0.6rem', cursor: 'pointer', fontSize: '0.72rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                    onClick={() => {
                      navigator.clipboard.writeText(networkInfo.primaryVmHostIp || '192.168.54.1');
                      toastEmitter.show('Đã sao chép IP', `Đã sao chép IP máy host: ${networkInfo.primaryVmHostIp || '192.168.54.1'} để dùng trong Kali`, 'success');
                    }}
                    title="Sao chép IP máy host để dùng trong Kali"
                  >
                    <i className="fa-solid fa-copy"></i>
                    <span>Sao chép IP Kali</span>
                  </button>
                </div>
              </div>
            )}

            {/* Danh Sách Tin Nhắn */}
            <div className="chat-messages-viewport">

              {messages.map((msg, index) => {
                const isAssistant = msg.role === 'assistant';
                return (
                  <div
                    key={index}
                    className={`chat-message-row ${isAssistant ? 'assistant-row' : 'user-row'}`}
                  >
                    {/* Avatar */}
                    <div className="message-avatar">
                      {isAssistant ? (
                        <div className="avatar-assistant-circle">
                          <i className="fa-solid fa-shield-halved"></i>
                        </div>
                      ) : (
                        <div className="avatar-user-circle">
                          <i className="fa-solid fa-user-shield"></i>
                        </div>
                      )}
                    </div>

                    {/* Khung nội dung */}
                    <div className="message-bubble-wrapper">
                      <div className="message-meta-header">
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                          <span className="message-sender-name">
                            {isAssistant ? 'Trợ Lý AI' : 'Bạn'}
                          </span>
                          {isAssistant && (
                            <span style={{
                              fontSize: '0.68rem',
                              fontWeight: 600,
                              background: 'rgba(56, 189, 248, 0.15)',
                              color: '#38bdf8',
                              border: '1px solid rgba(56, 189, 248, 0.3)',
                              borderRadius: '4px',
                              padding: '1px 6px',
                            }}>
                              AI Engine
                            </span>
                          )}
                        </div>
                        {msg.time && <span className="message-timestamp">{msg.time}</span>}
                      </div>

                      <div className={`message-bubble ${isAssistant ? 'assistant-bubble' : 'user-bubble'}`}>
                        {isAssistant ? (
                          <FormattedAiText text={msg.text} />
                        ) : (
                          <div className="user-text-content">{msg.text}</div>
                        )}
                      </div>

                      {/* Nút hành động nhanh trên tin nhắn AI */}
                      {isAssistant && (
                        <div className="message-actions-bar">
                          <button
                            type="button"
                            className="msg-action-btn"
                            onClick={() => handleCopyMessage(msg.text, index)}
                            title="Sao chép toàn bộ phản hồi"
                          >
                            {copyFeedbackIndex === index ? (
                              <>
                                <i className="fa-solid fa-check" style={{ color: '#10b981' }}></i>
                                <span style={{ color: '#10b981' }}>Đã sao chép!</span>
                              </>
                            ) : (
                              <>
                                <i className="fa-regular fa-copy"></i>
                                <span>Sao chép</span>
                              </>
                            )}
                          </button>
                          <span className="ai-verified-badge">
                            <i className="fa-solid fa-circle-check"></i> Đã đối chiếu tri thức ATTT
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {/* Loading Indicator */}
              {loading && (
                <div className="chat-message-row assistant-row loading-row">
                  <div className="message-avatar">
                    <div className="avatar-assistant-circle pulsing">
                      <i className="fa-solid fa-circle-notch fa-spin"></i>
                    </div>
                  </div>
                  <div className="message-bubble-wrapper">
                    <div className="message-meta-header">
                      <span className="message-sender-name">Trợ Lý AI</span>
                      <span className="message-timestamp">Đang tính toán...</span>
                    </div>
                    <div className="message-bubble assistant-bubble loading-bubble">
                      <div className="typing-indicator-wave">
                        <span></span>
                        <span></span>
                        <span></span>
                      </div>
                      <span className="loading-status-text">
                        AI đang đọc dữ liệu rà quét và phân tích ma trận bảo mật...
                      </span>
                    </div>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* ================= 3. INPUT AREA ================= */}
            <div className="cyber-chat-input-panel">
              <div className="input-toolbar-top" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div className="context-indicator-tag">
                    <i className="fa-solid fa-crosshairs"></i>
                    <span>Đang gắn bối cảnh: <strong>{targetName}</strong></span>
                  </div>
                  <button
                    type="button"
                    onClick={() => setShowContextAttachment(!showContextAttachment)}
                    style={{
                      background: showContextAttachment ? '#1e3a8a' : '#1e293b',
                      border: '1px solid ' + (showContextAttachment ? '#3b82f6' : '#334155'),
                      color: showContextAttachment ? '#93c5fd' : '#cbd5e1',
                      borderRadius: '4px',
                      padding: '2px 8px',
                      fontSize: '0.72rem',
                      cursor: 'pointer',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                    title="Đính kèm kết quả đầu ra, log hoặc dữ liệu JSON"
                  >
                    <i className="fa-solid fa-file-code"></i>
                    <span>{showContextAttachment ? 'Ẩn ô kết quả' : 'Đính kèm kết quả / Log'}</span>
                    {attachedOutputLog && (
                      <span style={{ background: '#3b82f6', color: '#fff', borderRadius: '50%', width: '12px', height: '12px', fontSize: '9px', display: 'inline-flex', alignItems: 'center', justifyContent: 'center' }}>✓</span>
                    )}
                  </button>
                </div>
                <span className="shortcut-hint">
                  <kbd>Enter</kbd> để gửi • <kbd>Shift + Enter</kbd> xuống dòng
                </span>
              </div>

              {showContextAttachment && (
                <div style={{ padding: '0.5rem 0.75rem', background: '#0b1120', border: '1px solid #1e293b', borderRadius: '6px', marginBottom: '0.5rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <span style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600 }}>
                      <i className="fa-solid fa-terminal" style={{ marginRight: '4px', color: '#38bdf8' }}></i>
                      Dán dữ liệu đầu ra / Log hệ thống / Đoạn JSON BloodHound:
                    </span>
                    {attachedOutputLog && (
                      <button
                        type="button"
                        onClick={() => setAttachedOutputLog('')}
                        style={{ background: 'transparent', border: 'none', color: '#ef4444', fontSize: '0.7rem', cursor: 'pointer' }}
                      >
                        Xóa log
                      </button>
                    )}
                  </div>
                  <textarea
                    rows={3}
                    value={attachedOutputLog}
                    onChange={(e) => setAttachedOutputLog(e.target.value)}
                    placeholder="Dán kết quả lệnh kiểm tra, output Nmap hoặc JSON cấu hình Active Directory để AI đối chiếu và hướng dẫn..."
                    style={{
                      width: '100%',
                      background: '#030712',
                      border: '1px solid #334155',
                      color: '#a7f3d0',
                      fontFamily: 'monospace',
                      fontSize: '0.75rem',
                      borderRadius: '4px',
                      padding: '0.4rem 0.6rem',
                      resize: 'vertical',
                    }}
                  />
                </div>
              )}

              {/* Hai khung nhập liệu: Khung Gửi Kết Quả/Báo Lỗi & Khung Nhập Câu Hỏi (Căn chỉnh thu hẹp, có thể tắt hoặc thu gọn) */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem' }}>
                
                {/* KHUNG 1: GỬI KẾT QUẢ BƯỚC / BÁO LỖI (Có thể thu hẹp hoặc tắt hẳn [X]) */}
                {messages.length > 1 && messages[messages.length - 1].role === 'assistant' && showStepResultBox && (
                  <div
                    style={{
                      background: isStepResultCollapsed ? '#0f172a' : 'rgba(15, 23, 42, 0.95)',
                      border: `1px solid ${stepResultStatus === 'ERROR' ? 'rgba(239, 68, 68, 0.45)' : 'rgba(16, 185, 129, 0.45)'}`,
                      borderRadius: '8px',
                      padding: isStepResultCollapsed ? '0.3rem 0.65rem' : '0.45rem 0.75rem',
                      boxShadow: '0 2px 10px rgba(0, 0, 0, 0.35)',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    {/* Header của Khung 1 */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 700, color: stepResultStatus === 'ERROR' ? '#f87171' : '#34d399', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                          <i className={stepResultStatus === 'ERROR' ? 'fa-solid fa-triangle-exclamation' : 'fa-solid fa-terminal'}></i>
                          <span>{stepResultStatus === 'ERROR' ? 'Báo Lỗi Bước Thực Hiện' : 'Kết Quả Bước Thực Hiện'}</span>
                        </span>

                        {!isStepResultCollapsed && (
                          <div style={{ display: 'flex', gap: '0.25rem', marginLeft: '0.35rem' }}>
                            <button
                              type="button"
                              style={{
                                fontSize: '0.68rem',
                                padding: '0.15rem 0.45rem',
                                borderRadius: '4px',
                                border: '1px solid ' + (stepResultStatus === 'SUCCESS' ? '#10b981' : '#334155'),
                                background: stepResultStatus === 'SUCCESS' ? 'rgba(16, 185, 129, 0.2)' : 'transparent',
                                color: stepResultStatus === 'SUCCESS' ? '#34d399' : '#94a3b8',
                                cursor: 'pointer',
                                fontWeight: 600,
                              }}
                              onClick={() => setStepResultStatus('SUCCESS')}
                            >
                              <i className="fa-solid fa-circle-check"></i> Đạt / Có output
                            </button>
                            <button
                              type="button"
                              style={{
                                fontSize: '0.68rem',
                                padding: '0.15rem 0.45rem',
                                borderRadius: '4px',
                                border: '1px solid ' + (stepResultStatus === 'ERROR' ? '#ef4444' : '#334155'),
                                background: stepResultStatus === 'ERROR' ? 'rgba(239, 68, 68, 0.2)' : 'transparent',
                                color: stepResultStatus === 'ERROR' ? '#f87171' : '#94a3b8',
                                cursor: 'pointer',
                                fontWeight: 600,
                              }}
                              onClick={() => setStepResultStatus('ERROR')}
                            >
                              <i className="fa-solid fa-bug"></i> Bị lỗi
                            </button>
                          </div>
                        )}
                      </div>

                      {/* Hành động nhanh & Nút Thu hẹp / Tắt */}
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                        {!loading && (
                          <button
                            type="button"
                            style={{
                              fontSize: '0.7rem',
                              padding: '0.15rem 0.5rem',
                              border: '1px solid rgba(56, 189, 248, 0.4)',
                              borderRadius: '4px',
                              color: '#38bdf8',
                              background: 'transparent',
                              cursor: 'pointer',
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '0.3rem',
                            }}
                            onClick={() => handleSend('Tôi đã thực hiện xong bước trên và không có lỗi gì phát sinh. Hãy hướng dẫn tôi BƯỚC TIẾP THEO!', 'Đã xong bước trên, tiếp tục')}
                            title="Bỏ qua việc dán output, chuyển ngay sang bước tiếp"
                          >
                            <i className="fa-solid fa-forward-step"></i> Đã xong bước trên ➔
                          </button>
                        )}

                        {/* Nút Thu hẹp / Mở rộng */}
                        <button
                          type="button"
                          style={{
                            fontSize: '0.7rem',
                            padding: '0.15rem 0.45rem',
                            border: '1px solid #334155',
                            borderRadius: '4px',
                            color: '#94a3b8',
                            background: 'transparent',
                            cursor: 'pointer',
                          }}
                          onClick={() => setIsStepResultCollapsed(!isStepResultCollapsed)}
                          title={isStepResultCollapsed ? 'Mở rộng khung nhập kết quả' : 'Thu hẹp khung nhập kết quả'}
                        >
                          <i className={`fa-solid ${isStepResultCollapsed ? 'fa-chevron-down' : 'fa-chevron-up'}`}></i>
                          <span style={{ marginLeft: '3px' }}>{isStepResultCollapsed ? 'Mở rộng' : 'Thu hẹp'}</span>
                        </button>

                        {/* Nút Tắt hẳn khung kết quả [X] */}
                        <button
                          type="button"
                          style={{
                            fontSize: '0.7rem',
                            padding: '0.15rem 0.45rem',
                            border: '1px solid rgba(239, 68, 68, 0.3)',
                            borderRadius: '4px',
                            color: '#ef4444',
                            background: 'transparent',
                            cursor: 'pointer',
                          }}
                          onClick={() => setShowStepResultBox(false)}
                          title="Tắt khung gửi kết quả (có thể bật lại bất cứ lúc nào)"
                        >
                          <i className="fa-solid fa-xmark"></i> Tắt
                        </button>
                      </div>
                    </div>

                    {/* Nội dung khi mở rộng: Textarea dán output + nút gửi kết quả */}
                    {!isStepResultCollapsed && (
                      <div style={{ marginTop: '0.35rem' }}>
                        <textarea
                          rows={2}
                          value={stepResultOutput}
                          onChange={(e) => setStepResultOutput(e.target.value)}
                          placeholder={
                            stepResultStatus === 'SUCCESS'
                              ? "Dán output terminal, curl response, status code, hoặc kết quả vừa chạy ở bước trên..."
                              : "Dán thông báo lỗi (Error message, Connection refused, 403 Forbidden, syntax error...) để AI sửa..."
                          }
                          disabled={loading}
                          style={{
                            width: '100%',
                            fontFamily: 'Consolas, monospace',
                            fontSize: '0.82rem',
                            lineHeight: '1.4',
                            background: '#030712',
                            border: `1px solid ${stepResultStatus === 'ERROR' ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
                            color: stepResultStatus === 'ERROR' ? '#fca5a5' : '#a7f3d0',
                            borderRadius: '5px',
                            padding: '0.35rem 0.6rem',
                            minHeight: '44px',
                            maxHeight: '100px',
                            resize: 'vertical',
                            marginBottom: '0.35rem',
                            boxSizing: 'border-box',
                            outline: 'none',
                          }}
                        />

                        <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: '0.4rem' }}>
                          {stepResultOutput.trim() && (
                            <button
                              type="button"
                              style={{
                                fontSize: '0.7rem',
                                padding: '0.15rem 0.45rem',
                                border: '1px solid #334155',
                                borderRadius: '4px',
                                color: '#94a3b8',
                                background: 'transparent',
                                cursor: 'pointer',
                              }}
                              onClick={() => setStepResultOutput('')}
                            >
                              Xóa
                            </button>
                          )}
                          <button
                            type="button"
                            disabled={!stepResultOutput.trim() || loading}
                            onClick={handleSubmitStepResult}
                            style={{
                              fontSize: '0.75rem',
                              padding: '0.22rem 0.85rem',
                              fontWeight: 600,
                              borderRadius: '4px',
                              border: 'none',
                              color: '#fff',
                              background: stepResultStatus === 'ERROR' ? '#ef4444' : '#059669',
                              cursor: !stepResultOutput.trim() || loading ? 'not-allowed' : 'pointer',
                              opacity: !stepResultOutput.trim() || loading ? 0.5 : 1,
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: '4px',
                            }}
                          >
                            <i className={stepResultStatus === 'ERROR' ? 'fa-solid fa-wrench' : 'fa-solid fa-paper-plane'}></i>
                            <span>
                              {stepResultStatus === 'ERROR' ? 'Gửi Lỗi Cho AI Sửa' : 'Gửi Kết Quả Cho AI Đánh Giá'}
                            </span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* KHUNG 2: KHUNG NHẬP CÂU HỎI / CHAT CHÍNH (Căn chỉnh thu hẹp, thanh lịch) */}
                <div
                  style={{
                    background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.8))',
                    border: '1px solid rgba(56, 189, 248, 0.35)',
                    borderRadius: '8px',
                    padding: '0.45rem 0.75rem',
                    boxShadow: '0 2px 12px rgba(0, 0, 0, 0.35)',
                  }}
                >
                  {/* Thanh phụ trợ nếu Khung Gửi Kết Quả đang bị TẮT */}
                  {!showStepResultBox && messages.length > 1 && (
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem', paddingBottom: '0.25rem', borderBottom: '1px dashed rgba(148, 163, 184, 0.15)' }}>
                      <span style={{ fontSize: '0.72rem', color: '#94a3b8' }}>
                        <i className="fa-solid fa-message" style={{ marginRight: '4px', color: '#38bdf8' }}></i>
                        Đặt câu hỏi bảo mật / Yêu cầu giải pháp
                      </span>
                      <button
                        type="button"
                        style={{
                          fontSize: '0.68rem',
                          padding: '0.12rem 0.5rem',
                          border: '1px solid rgba(16, 185, 129, 0.4)',
                          borderRadius: '4px',
                          color: '#34d399',
                          background: 'transparent',
                          cursor: 'pointer',
                        }}
                        onClick={() => {
                          setShowStepResultBox(true);
                          setIsStepResultCollapsed(false);
                        }}
                      >
                        <i className="fa-solid fa-plus"></i> Bật khung gửi kết quả bước
                      </button>
                    </div>
                  )}

                  {/* Textarea nhập câu hỏi */}
                  <textarea
                    ref={textareaRef}
                    placeholder={`Đặt câu hỏi bảo mật, phân tích lỗ hổng hoặc yêu cầu giải pháp cho ${targetName}... (Enter để gửi, Shift+Enter xuống dòng)`}
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
                      background: '#030712',
                      border: '1px solid rgba(56, 189, 248, 0.35)',
                      color: '#f8fafc',
                      borderRadius: '6px',
                      padding: '0.45rem 0.65rem',
                      marginBottom: '0.35rem',
                      minHeight: '48px',
                      maxHeight: '130px',
                      resize: 'vertical',
                      boxSizing: 'border-box',
                      outline: 'none',
                    }}
                  />

                  {/* Toolbar dưới của Khung 2 */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.4rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                      <span style={{ fontSize: '0.7rem', color: '#64748b' }}>
                        <kbd style={{ background: '#1e293b', padding: '1px 4px', borderRadius: '3px', color: '#cbd5e1' }}>Enter</kbd> gửi • <kbd style={{ background: '#1e293b', padding: '1px 4px', borderRadius: '3px', color: '#cbd5e1' }}>Shift+Enter</kbd> xuống dòng
                      </span>
                      {inputText.trim() && (
                        <button
                          type="button"
                          style={{ fontSize: '0.68rem', padding: '0.12rem 0.4rem', border: '1px solid #334155', borderRadius: '4px', color: '#94a3b8', background: 'transparent', cursor: 'pointer' }}
                          onClick={() => setInputText('')}
                        >
                          Xóa
                        </button>
                      )}
                      {inputText.length > 0 && (
                        <span style={{ fontSize: '0.68rem', color: '#64748b' }}>
                          {inputText.length} ký tự
                        </span>
                      )}
                    </div>

                    <button
                      type="button"
                      disabled={loading || !inputText.trim()}
                      style={{
                        fontSize: '0.8rem',
                        padding: '0.35rem 1.1rem',
                        border: 'none',
                        borderRadius: '6px',
                        color: '#fff',
                        background: inputText.trim() && !loading ? 'linear-gradient(135deg, #0284c7, #4f46e5)' : '#1e293b',
                        opacity: !inputText.trim() || loading ? 0.5 : 1,
                        cursor: !inputText.trim() || loading ? 'not-allowed' : 'pointer',
                        fontWeight: 700,
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.4rem',
                        boxShadow: inputText.trim() && !loading ? '0 0 15px rgba(2, 132, 199, 0.4)' : 'none'
                      }}
                      onClick={() => handleSend()}
                    >
                      {loading ? (
                        <i className="fa-solid fa-circle-notch fa-spin"></i>
                      ) : (
                        <>
                          <i className="fa-solid fa-paper-plane"></i>
                          <span>Gửi Câu Hỏi Cho AI</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>

              </div>
            </div>

          </div>
        </div>

      </div>
    </div>
  );
}

