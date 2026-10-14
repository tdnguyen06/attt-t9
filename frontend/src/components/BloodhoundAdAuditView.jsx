import React, { useState, useRef, useEffect, useMemo } from 'react';
import { apiClient, toastEmitter } from '../services/api';
import FormattedAiText from './FormattedAiText';
import html2pdf from 'html2pdf.js';

export default function BloodhoundAdAuditView({ onAskAi }) {
  const [loading, setLoading] = useState(false);
  const [aiAnalyzing, setAiAnalyzing] = useState(false);
  const [data, setData] = useState(null);
  const [rawJsonText, setRawJsonText] = useState('');
  const [activeSubTab, setActiveSubTab] = useState('findings'); // 'findings' | 'ai'
  const [showConfigForm, setShowConfigForm] = useState(true);
  const [inputMode, setInputMode] = useState('ldap'); // 'ldap' | 'upload' | 'paste'
  const fileInputRef = useRef(null);
  const [showPassword, setShowPassword] = useState(false);
  const [findingFilter, setFindingFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [isExportingPdf, setIsExportingPdf] = useState(false);

  // Quản lý lịch sử các lần quét AD từ cơ sở dữ liệu backend
  const [scanHistory, setScanHistory] = useState([]);
  const [selectedHistoryId, setSelectedHistoryId] = useState('');
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Chọn một lần quét từ lịch sử
  const selectHistoryItem = (item, showNotification = true) => {
    if (!item || !item.summary) return;
    const summary = typeof item.summary === 'string' ? JSON.parse(item.summary) : item.summary;
    setSelectedHistoryId(String(item.taskId || ''));
    if (!summary.aiAnalysis && item.aiExplanation) {
      try {
        const parsedExpl = typeof item.aiExplanation === 'string' ? JSON.parse(item.aiExplanation) : item.aiExplanation;
        summary.aiAnalysis = parsedExpl?.analysis || parsedExpl?.explanation || item.aiExplanation;
      } catch (e) {
        summary.aiAnalysis = item.aiExplanation;
      }
    }
    setData(summary);
    setRawJsonText(JSON.stringify(summary, null, 2));
    setShowConfigForm(false);
    setActiveSubTab(summary?.aiAnalysis ? 'ai' : 'findings');

    const domainName = item.domain || summary?.domainName || '';
    const hostTarget = item.target || '';
    const authUser = item.authenticatedUser || summary?.authenticatedUser || '';

    setLdapConfig(prev => ({
      ...prev,
      domain: domainName,
      host: hostTarget,
      baseDn: domainName ? domainName.split('.').filter(Boolean).map(p => `DC=${p}`).join(',') : '',
    }));

    try {
      if (domainName || hostTarget) {
        localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
          taskId: item.taskId,
          assessmentId: item.assessmentId,
          domain: domainName,
          host: hostTarget,
          port: 389,
          authenticatedUser: authUser,
          hasValidCredentials: !!authUser,
          summary: summary,
          rawJson: summary,
          scannedAt: item.createdAt || new Date().toISOString()
        }));
      }
    } catch (e) {}

    if (showNotification) {
      toastEmitter.show('Lịch sử kiểm toán AD', `Đã nạp kết quả kiểm toán (Mục tiêu: ${hostTarget} / ${domainName}).`, 'success');
    }
  };

  // Tải danh sách lịch sử quét từ backend API
  const loadHistory = async (autoSelectLatest = false) => {
    try {
      setLoadingHistory(true);
      const res = await apiClient.get('/bloodhound/history');
      if (Array.isArray(res)) {
        setScanHistory(res);
        if (autoSelectLatest && res.length > 0) {
          selectHistoryItem(res[0], false);
        }
      }
    } catch (err) {
      console.error('Không thể tải lịch sử kiểm thử Active Directory:', err);
    } finally {
      setLoadingHistory(false);
    }
  };

  // Xóa lần quét hiện tại khỏi Database
  const handleDeleteCurrentHistory = async () => {
    if (!selectedHistoryId) return;
    if (!window.confirm('Bạn có chắc chắn muốn xóa bản ghi kiểm toán này khỏi cơ sở dữ liệu không?')) return;
    try {
      await apiClient.delete(`/bloodhound/history/${selectedHistoryId}`);
      toastEmitter.show('Đã xóa', 'Đã xóa thành công bản ghi kiểm toán khỏi hệ thống.', 'success');
      localStorage.removeItem('attt_bloodhound_audit_data');
      setSelectedHistoryId('');
      setData(null);
      setRawJsonText('');
      setShowConfigForm(true);
      await loadHistory(false);
    } catch (err) {
      toastEmitter.show('Lỗi', err?.message || 'Không thể xóa lần quét.', 'error');
    }
  };

  // Xóa toàn bộ lịch sử quét AD cũ khỏi Database
  const handleDeleteAllHistory = async () => {
    if (!window.confirm('Bạn có chắc chắn muốn xóa TOÀN BỘ lịch sử các lần quét AD cũ khỏi cơ sở dữ liệu không?')) return;
    try {
      await apiClient.delete('/bloodhound/history/all');
      toastEmitter.show('Đã dọn sạch', 'Đã xóa toàn bộ lịch sử các lần quét AD cũ khỏi hệ thống.', 'success');
      localStorage.removeItem('attt_bloodhound_audit_data');
      setSelectedHistoryId('');
      setData(null);
      setRawJsonText('');
      setShowConfigForm(true);
      await loadHistory(false);
    } catch (err) {
      toastEmitter.show('Lỗi', err?.message || 'Không thể dọn sạch lịch sử.', 'error');
    }
  };

  // Khởi tạo: Tự động nạp lần quét AD mới nhất từ Database nếu có
  useEffect(() => {
    loadHistory(true);
  }, []);

  // Form kết nối trực tiếp LDAP / LDAPS - Bắt buộc tài khoản xác thực (Không dùng Mock Data)
  const [ldapConfig, setLdapConfig] = useState({
    domain: '',
    username: '',
    password: '',
    host: '',
    port: '389',
    useSsl: false,
    baseDn: '',
  });

  // Dán JSON trực tiếp từ SharpHound
  const [pasteJsonInput, setPasteJsonInput] = useState('');

  // Tự động gợi ý Base DN khi người dùng nhập Domain
  const handleDomainChange = (domainVal) => {
    const trimmed = domainVal.trim();
    const parts = trimmed.split('.').filter(Boolean);
    const suggestedBase = parts.map(p => `DC=${p}`).join(',');
    setLdapConfig(prev => ({
      ...prev,
      domain: domainVal,
      baseDn: suggestedBase || prev.baseDn
    }));
  };

  // 1. Quét & thu thập trực tiếp từ Active Directory qua LDAP / LDAPS
  const handleConnectAndScan = async () => {
    if (!ldapConfig.domain?.trim()) {
      toastEmitter.show('Thiếu thông tin', 'Vui lòng nhập Tên Miền Active Directory.', 'warning');
      return;
    }
    if (!ldapConfig.host?.trim()) {
      toastEmitter.show('Thiếu thông tin', 'Vui lòng nhập Địa Chỉ Máy Chủ Domain Controller.', 'warning');
      return;
    }
    if (!ldapConfig.username?.trim()) {
      toastEmitter.show('Thiếu thông tin', 'Vui lòng nhập Tên Tài Khoản AD. Active Directory không cho phép quét ẩn danh.', 'warning');
      return;
    }
    if (!ldapConfig.password) {
      toastEmitter.show('Thiếu thông tin', 'Vui lòng nhập Mật Khẩu Tài Khoản AD.', 'warning');
      return;
    }

    try {
      setLoading(true);
      const payload = {
        method: ldapConfig.useSsl ? 'LDAPS' : 'LDAP',
        host: ldapConfig.host.trim(),
        port: parseInt(ldapConfig.port, 10) || (ldapConfig.useSsl ? 636 : 389),
        useSsl: ldapConfig.useSsl,
        domain: ldapConfig.domain.trim(),
        username: ldapConfig.username.trim(),
        password: ldapConfig.password,
        baseDn: ldapConfig.baseDn?.trim() || undefined,
      };

      toastEmitter.show('Kết nối LDAP', `Đang xác thực với Domain Controller ${payload.host}:${payload.port} (${payload.domain})...`, 'info');
      const res = await apiClient.post('/bloodhound/scan-environment', payload);
      if (res && res.summary) {
        setData(res.summary);
        setRawJsonText(typeof res.rawJson === 'string' ? res.rawJson : JSON.stringify(res.rawJson, null, 2));
        setShowConfigForm(false);
        if (res.taskId) {
          setSelectedHistoryId(String(res.taskId));
        }
        try {
          localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
            taskId: res.taskId,
            assessmentId: res.assessmentId,
            domain: res.domain || ldapConfig.domain || '',
            host: ldapConfig.host || '',
            port: ldapConfig.port || 389,
            authenticatedUser: res.authenticatedUser || ldapConfig.username || '',
            password: ldapConfig.password || '',
            hasValidCredentials: !!(res.authenticatedUser || ldapConfig.username),
            summary: res.summary,
            rawJson: res.rawJson,
            scannedAt: res.createdAt || new Date().toISOString()
          }));
        } catch (e) {}
        if (res.summary?.aiAnalysis) {
          setActiveSubTab('ai');
        } else {
          setActiveSubTab('findings');
        }
        toastEmitter.show('Thành công', `Đã kết nối, trích xuất ${res.summary?.totalObjectsScanned || 0} đối tượng vào Database!`, 'success');
        await loadHistory(false);
      }
    } catch (err) {
      if (!err?.response) {
        toastEmitter.show('Lỗi kết nối Active Directory', err?.message || 'Không thể kết nối đến máy chủ Active Directory.', 'error');
      }
    } finally {
      setLoading(false);
    }
  };

  // 2. Tải lên tệp JSON BloodHound xuất từ SharpHound / BloodHound.py
  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      setLoading(true);
      toastEmitter.show('Tự động phân tích AI', `Đang tải tệp ${file.name} và phân tích ma trận quyền...`, 'info');
      const summary = await apiClient.post('/bloodhound/upload?includeAi=true', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      const reader = new FileReader();
      reader.onload = (event) => {
        setRawJsonText(event.target.result);
      };
      reader.readAsText(file);

      setData(summary);
      setShowConfigForm(false);
      try {
        localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
          domain: summary?.domainName || ldapConfig.domain || 'Active Directory',
          host: ldapConfig.host,
          summary: summary,
          scannedAt: new Date().toISOString()
        }));
      } catch (e) {}
      if (summary?.aiAnalysis) {
        setActiveSubTab('ai');
      } else {
        setActiveSubTab('findings');
      }
      toastEmitter.show('Phân tích thành công', `Bóc tách thành công tệp ${file.name} (${summary?.totalObjectsScanned || 0} đối tượng thực tế). Đã nạp vào Chatbot AI!`, 'success');
    } catch (err) {
      toastEmitter.show('Lỗi phân tích tệp', err?.message || 'Không thể đọc tệp BloodHound JSON.', 'error');
    } finally {
      setLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  // 3. Phân tích văn bản JSON dán thủ công
  const handlePasteJsonSubmit = async () => {
    if (!pasteJsonInput.trim()) {
      toastEmitter.show('Thiếu dữ liệu', 'Vui lòng dán nội dung tệp JSON BloodHound vào khung nhập.', 'warning');
      return;
    }

    try {
      setLoading(true);
      toastEmitter.show('Bóc tách JSON', 'Đang xác thực và phân tích dữ liệu JSON vừa nhập...', 'info');
      const res = await apiClient.post('/bloodhound/ai-analyze', pasteJsonInput.trim(), {
        headers: { 'Content-Type': 'text/plain' },
      });

      if (res) {
        setData(res);
        setRawJsonText(pasteJsonInput.trim());
        setShowConfigForm(false);
        try {
          localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
            domain: res?.domainName || 'Active Directory',
            summary: res,
            scannedAt: new Date().toISOString()
          }));
        } catch (e) {}
        setActiveSubTab(res.aiAnalysis ? 'ai' : 'findings');
        toastEmitter.show('Thành công', `Đã nạp và phân tích ${res.totalObjectsScanned || 0} đối tượng từ JSON. Đã nạp vào Chatbot AI!`, 'success');
      }
    } catch (err) {
      toastEmitter.show('Lỗi xử lý JSON', err?.message || 'Định dạng JSON BloodHound không hợp lệ.', 'error');
    } finally {
      setLoading(false);
    }
  };

  // Phân tích lại với AI cho JSON hiện tại
  const handleAiAnalyze = async () => {
    if (!rawJsonText) {
      toastEmitter.show('Chưa có dữ liệu', 'Vui lòng nạp dữ liệu Active Directory trước.', 'warning');
      return;
    }
    try {
      setAiAnalyzing(true);
      toastEmitter.show('AI Security Analyst', 'Đang gửi dữ liệu BloodHound cho AI phân tích...', 'info');
      const res = await apiClient.post('/bloodhound/ai-analyze', rawJsonText, {
        headers: { 'Content-Type': 'text/plain' },
      });
      if (res) {
        setData(res);
        try {
          localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
            domain: res?.domainName || data?.domainName || 'Active Directory',
            summary: res,
            scannedAt: new Date().toISOString()
          }));
        } catch (e) {}
        setActiveSubTab('ai');
        toastEmitter.show('Thành công', 'AI đã hoàn tất báo cáo đánh giá an ninh Active Directory.', 'success');
      }
    } catch (err) {
      toastEmitter.show('Lỗi phân tích AI', err?.message || 'Không thể gọi AI.', 'error');
    } finally {
      setAiAnalyzing(false);
    }
  };

  // 4. Xuất file PDF Báo Cáo Kiểm Thử Active Directory Toàn Diện
  const handleExportPdf = async () => {
    if (!data) {
      toastEmitter.show('Chưa có dữ liệu', 'Vui lòng thực hiện kiểm thử hoặc chọn một bản ghi lịch sử Active Directory để xuất báo cáo.', 'warning');
      return;
    }

    setIsExportingPdf(true);
    toastEmitter.show('Đang xuất file PDF', `Đang kết xuất báo cáo an ninh Active Directory cho miền ${data?.domainName || ldapConfig.domain || 'AD'}...`, 'info');

    try {
      const escapeHtml = (str) => {
        if (!str) return '';
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
      };

      const domain = data.domainName || ldapConfig.domain || 'Active Directory';
      const host = ldapConfig.host || data.host || '(Theo cấu hình Domain Controller)';
      const user = ldapConfig.username || data.authenticatedUser || 'Chuyên viên kiểm thử';
      const dtf = new Date().toLocaleString('vi-VN');

      const criticalCount = data.criticalRiskCount || 0;
      const highCount = data.highRiskCount || 0;
      const totalObjects = data.totalObjectsScanned || data.totalObjects || 0;
      const highRiskFindings = data.highRiskFindings || [];

      const overallRisk = criticalCount > 0 ? 'CRITICAL' : highCount > 0 ? 'HIGH' : 'MEDIUM';
      const riskColor = overallRisk === 'CRITICAL' ? '#dc2626' : overallRisk === 'HIGH' ? '#ea580c' : '#d97706';

      let aiText = '';
      if (data.aiAnalysis) {
        aiText = typeof data.aiAnalysis === 'string' ? data.aiAnalysis : JSON.stringify(data.aiAnalysis);
      }

      // Xây dựng bảng ma trận phân quyền nguy cấp
      const findingsTableHtml = highRiskFindings.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th style="width: 35px;">STT</th>
              <th style="width: 140px;">Tài Khoản Nguồn</th>
              <th style="width: 120px;">Quan Hệ Quyền</th>
              <th style="width: 140px;">Đối Tượng Đích</th>
              <th style="width: 75px;">Rủi Ro</th>
              <th>Nguy Cơ Kỹ Thuật & Biện Pháp Khắc Phục</th>
            </tr>
          </thead>
          <tbody>
            ${highRiskFindings.map((f, idx) => `
              <tr>
                <td style="text-align: center; color: #64748b; font-weight: bold;">${idx + 1}</td>
                <td><code style="color: #0369a1; font-weight: bold;">${escapeHtml(f.sourcePrincipal)}</code></td>
                <td><span style="display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 800; background: #fee2e2; color: #b91c1c;">${escapeHtml(f.relationshipType)}</span></td>
                <td><code style="color: #b45309; font-weight: bold;">${escapeHtml(f.targetObject)}</code></td>
                <td><span style="display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: bold; color: #ffffff; background: ${f.riskLevel === 'CRITICAL' ? '#dc2626' : '#ea580c'};">${escapeHtml(f.riskLevel)}</span></td>
                <td>
                  <div style="font-weight: 600; color: #1e293b; margin-bottom: 3px;">${escapeHtml(f.description)}</div>
                  ${f.remediation ? `<div style="color: #15803d; font-size: 11.5px; background: #f0fdf4; padding: 3px 6px; border-radius: 4px; border-left: 2.5px solid #16a34a; margin-top: 3px;"><strong>Khắc phục:</strong> ${escapeHtml(f.remediation)}</div>` : ''}
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : '<p style="color: #16a34a; font-weight: 600;">Không phát hiện liên kết ACL leo quyền nguy hiểm trong dữ liệu kiểm toán.</p>';

      const reportStyles = `
        @page {
          size: A4;
          margin: 12mm 10mm 15mm 10mm;
        }
        * { box-sizing: border-box; }
        body {
          font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
          color: #1e293b;
          background: #ffffff;
          line-height: 1.5;
          font-size: 13px;
          margin: 0;
          padding: 0;
        }
        .report-header {
          border-bottom: 3px solid #7c3aed;
          padding-bottom: 14px;
          margin-bottom: 18px;
          display: flex;
          justify-content: space-between;
          align-items: flex-end;
        }
        .brand-title {
          font-size: 19px;
          font-weight: 800;
          color: #0f172a;
          letter-spacing: 0.02em;
        }
        .doc-type {
          font-size: 12px;
          color: #64748b;
          font-weight: 600;
          text-transform: uppercase;
          margin-top: 3px;
        }
        .risk-badge {
          display: inline-block;
          padding: 6px 16px;
          border-radius: 6px;
          font-weight: 800;
          font-size: 13px;
          color: #ffffff;
          background: ${riskColor};
          box-shadow: 0 2px 6px rgba(0,0,0,0.15);
        }
        .meta-grid {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 10px;
          background: #f8fafc;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 12px 16px;
          margin-bottom: 18px;
        }
        .meta-item { font-size: 12px; }
        .meta-item strong { color: #334155; }
        .meta-item span { color: #0f172a; font-weight: 600; }
        .stat-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 10px;
          margin-bottom: 18px;
        }
        .stat-box {
          background: #ffffff;
          border: 1px solid #cbd5e1;
          border-radius: 6px;
          padding: 10px;
          text-align: center;
        }
        .stat-val { font-size: 20px; font-weight: 800; color: #0f172a; }
        .stat-lbl { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600; margin-top: 3px; }
        .section {
          margin-bottom: 20px;
          page-break-inside: avoid;
        }
        .section-title {
          font-size: 14px;
          font-weight: 800;
          color: #6d28d9;
          border-bottom: 1.5px solid #cbd5e1;
          padding-bottom: 5px;
          margin-bottom: 10px;
          display: flex;
          align-items: center;
          gap: 8px;
        }
        .ai-box {
          background: #faf5ff;
          border: 1px solid #e9d5ff;
          border-left: 4px solid #8b5cf6;
          border-radius: 0 6px 6px 0;
          padding: 12px 14px;
          font-size: 12.5px;
          color: #3b0764;
          line-height: 1.6;
          white-space: pre-wrap;
        }
        .hard-box {
          background: #f0fdf4;
          border: 1px solid #bbf7d0;
          border-left: 4px solid #16a34a;
          border-radius: 0 6px 6px 0;
          padding: 12px 14px;
          font-size: 12px;
          color: #14532d;
          line-height: 1.6;
        }
        table {
          width: 100%;
          border-collapse: collapse;
          margin-top: 6px;
          font-size: 11.5px;
          page-break-inside: avoid;
        }
        th {
          background: #f1f5f9;
          padding: 8px 10px;
          text-align: left;
          font-weight: 700;
          color: #334155;
          border-bottom: 2px solid #cbd5e1;
          font-size: 11px;
        }
        td {
          padding: 8px 10px;
          border-bottom: 1px solid #e2e8f0;
        }
        code {
          font-family: 'Consolas', monospace;
          background: #f1f5f9;
          padding: 2px 4px;
          border-radius: 3px;
          color: #7c3aed;
          font-size: 11px;
        }
        .signature-section {
          margin-top: 28px;
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 20px;
          page-break-inside: avoid;
        }
        .signature-box {
          border-top: 1px dashed #94a3b8;
          padding-top: 10px;
          text-align: center;
          font-size: 12px;
          color: #475569;
        }
        .report-footer {
          margin-top: 22px;
          border-top: 1px solid #e2e8f0;
          padding-top: 10px;
          font-size: 11px;
          color: #94a3b8;
          display: flex;
          justify-content: space-between;
        }
      `;

      const reportBodyHtml = `
        <div class="report-header">
          <div>
            <div class="brand-title">🛡️ ATTT PORTAL - BÁO CÁO KIỂM THỬ AN NINH ACTIVE DIRECTORY</div>
            <div class="doc-type">Kiểm Toán Ma Trận Phân Quyền & Nguy Cơ Leo Thang Đặc Quyền (BloodHound / LDAP)</div>
          </div>
          <div>
            <span class="risk-badge">RỦI RO: ${overallRisk}</span>
          </div>
        </div>

        <div class="meta-grid">
          <div class="meta-item"><strong>Miền Quản Trị (Domain):</strong> <span>${escapeHtml(domain)}</span></div>
          <div class="meta-item"><strong>Máy Chủ Điều Khiển (DC Host):</strong> <code>${escapeHtml(host)}</code></div>
          <div class="meta-item"><strong>Tài Khoản Xác Thực:</strong> <span>${escapeHtml(user)}</span></div>
          <div class="meta-item"><strong>Thời Điểm Xuất Báo Cáo:</strong> <span>${dtf}</span></div>
          <div class="meta-item"><strong>Tiêu Chuẩn Đánh Giá:</strong> <span>MITRE ATT&CK for Enterprise (TA0004, TA0006) • BloodHound Enterprise</span></div>
          <div class="meta-item"><strong>Phạm Vi Kiểm Thử:</strong> <span>Đối tượng Người dùng, Nhóm, Máy tính, GPO, ACLs, Quyền Quản trị Miền</span></div>
        </div>

        <div class="stat-grid">
          <div class="stat-box" style="border-top: 3px solid #7c3aed;">
            <div class="stat-val" style="color: #7c3aed;">${totalObjects}</div>
            <div class="stat-lbl">Đối Tượng AD Đã Quét</div>
          </div>
          <div class="stat-box" style="border-top: 3px solid #dc2626;">
            <div class="stat-val" style="color: #dc2626;">${criticalCount}</div>
            <div class="stat-lbl">ACL Nguy Cấp (Critical)</div>
          </div>
          <div class="stat-box" style="border-top: 3px solid #ea580c;">
            <div class="stat-val" style="color: #ea580c;">${highCount}</div>
            <div class="stat-lbl">ACL Rủi Ro Cao (High)</div>
          </div>
          <div class="stat-box" style="border-top: 3px solid #0284c7;">
            <div class="stat-val" style="color: #0284c7;">${criticalCount + highCount}</div>
            <div class="stat-lbl">Tổng Chuỗi Tấn Công</div>
          </div>
        </div>

        <!-- 1. Tóm tắt điều hành & Nhận định AI -->
        <div class="section">
          <div class="section-title">🧠 1. ĐÁNH GIÁ CHUYÊN SÂU & CHUỖI LEO QUYỀN TỪ TRỢ LÝ AN NINH AI</div>
          <div class="ai-box">
            ${escapeHtml(aiText || 'Hệ thống đã phân tích ma trận quyền hạn trên Active Directory. Đã bóc tách cấu trúc tài khoản, quyền thừa kế bất thường, nguy cơ Kerberoasting, AS-REP Roasting và các đường dẫn ngắn nhất có thể dẫn tới kiểm soát Domain Admins.')}
          </div>
        </div>

        <!-- 2. Ma trận quyền hạn nguy cấp -->
        <div class="section">
          <div class="section-title">📊 2. MA TRẬN PHÂN QUYỀN NGUY CẤP & CÁC ĐƯỜNG DẪN TẤN CÔNG (ACL MATRIX)</div>
          ${findingsTableHtml}
        </div>

        <!-- 3. Hướng dẫn khắc phục & Tăng cứng bảo mật AD -->
        <div class="section">
          <div class="section-title">🛡️ 3. KHUYẾN NGHỊ TĂNG CỨNG BẢO MẬT ACTIVE DIRECTORY (HARDENING ROADMAP)</div>
          <div class="hard-box">
            <strong>1. Triển khai Mô hình phân tầng (Active Directory Tiering Model):</strong> Cô lập hoàn toàn nhóm Tier 0 (Domain Controllers, Domain Admins) tách biệt khỏi Tier 1 (Server ứng dụng) và Tier 2 (Workstation người dùng).<br/>
            <strong>2. Áp dụng nhóm "Protected Users":</strong> Thêm toàn bộ tài khoản quản trị miền vào nhóm Protected Users để vô hiệu hóa NTLM, Credential Caching và hạn chế vé Kerberos TGT quá hạn.<br/>
            <strong>3. Triển khai LAPS (Local Administrator Password Solution):</strong> Ngăn chặn việc sử dụng chung mật khẩu quản trị viên cục bộ trên các máy tính tham gia domain, triệt tiêu kỹ thuật Pass-The-Hash lan truyền ngang hàng.<br/>
            <strong>4. Vô hiệu hóa giao thức RC4-HMAC:</strong> Bắt buộc áp dụng mã hóa Kerberos AES-128 / AES-256 đối với các tài khoản dịch vụ (gMSA) nhằm triệt tiêu lỗ hổng Kerberoasting.<br/>
            <strong>5. Rà soát định kỳ quyền thừa kế trên AdminSDHolder:</strong> Xóa bỏ các quyền dư thừa (GenericAll, WriteDacl, AllExtendedRights) được gán sai cho các tài khoản không đặc quyền.
          </div>
        </div>

        <!-- 4. Ký xác nhận -->
        <div class="signature-section">
          <div class="signature-box">
            <strong>Chuyên Viên Kiểm Thử AD (Security Auditor)</strong><br/><br/><br/>
            <span>${escapeHtml(user)}</span>
          </div>
          <div class="signature-box">
            <strong>Lãnh Đạo Phụ Trách An Toàn Thông Tin</strong><br/><br/><br/>
            <span>Xác nhận & Phê duyệt lưu hành</span>
          </div>
        </div>

        <div class="report-footer">
          <div>Xuất bởi: ATTT Portal Active Directory Audit Engine • Bản quyền thuộc Đơn vị An toàn thông tin</div>
          <div>Tài liệu bảo mật cao cấp - Chỉ lưu hành nội bộ</div>
        </div>
      `;

      const cleanDomain = domain.replace(/[^a-zA-Z0-9_\u00C0-\u024F\u1EA0-\u1EF9]/g, '_');
      const dateStr = new Date().toISOString().slice(0, 10);
      const pdfFileName = `Bao_Cao_Active_Directory_${cleanDomain}_${dateStr}.pdf`;

      // BƯỚC 1: XUẤT TỆP PDF THẬT TRỰC TIẾP VỀ MÁY TÍNH (DOWNLOAD FILE .PDF)
      const exportDiv = document.createElement('div');
      exportDiv.id = 'temp-ad-pdf-export-container';
      exportDiv.style.position = 'fixed';
      exportDiv.style.left = '-9999px';
      exportDiv.style.top = '0';
      exportDiv.style.width = '794px';
      exportDiv.style.backgroundColor = '#ffffff';
      exportDiv.style.color = '#1e293b';
      exportDiv.style.padding = '20px 24px';
      exportDiv.style.fontFamily = "'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif";
      exportDiv.innerHTML = `<style>${reportStyles}</style>${reportBodyHtml}`;

      document.body.appendChild(exportDiv);

      const pdfOpt = {
        margin: [10, 8, 12, 8],
        filename: pdfFileName,
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true, logging: false },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
        pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
      };

      try {
        await html2pdf().set(pdfOpt).from(exportDiv).save();
        toastEmitter.show(
          'Xuất file PDF thành công!',
          `Tệp "${pdfFileName}" đã được tải về máy của bạn.`,
          'success'
        );
      } catch (pdfErr) {
        console.warn('Lỗi html2pdf save AD:', pdfErr);
        toastEmitter.show('Cảnh báo xuất PDF', 'Đang chuyển sang chế độ in/lưu của trình duyệt...', 'warning');
      } finally {
        if (document.body.contains(exportDiv)) {
          document.body.removeChild(exportDiv);
        }
      }

      // BƯỚC 2: MỞ GIAO DIỆN XEM TRƯỚC VÀ IN ẤN TIỆN LỢI
      try {
        const previewWindow = window.open('', '_blank');
        if (previewWindow) {
          const fullHtml = `
            <!DOCTYPE html>
            <html lang="vi">
            <head>
              <meta charset="utf-8" />
              <title>BÁO CÁO KIỂM THỬ ACTIVE DIRECTORY - ${escapeHtml(domain)}</title>
              <style>
                ${reportStyles}
                .toolbar-header {
                  position: sticky;
                  top: 0;
                  background: #0f172a;
                  color: #f8fafc;
                  padding: 12px 20px;
                  display: flex;
                  justify-content: space-between;
                  align-items: center;
                  border-bottom: 2px solid #8b5cf6;
                  box-shadow: 0 4px 12px rgba(0,0,0,0.25);
                  z-index: 9999;
                  font-family: 'Segoe UI', Roboto, sans-serif;
                }
                .toolbar-btn {
                  background: #7c3aed;
                  color: #ffffff;
                  border: none;
                  padding: 7px 16px;
                  border-radius: 6px;
                  font-weight: 600;
                  font-size: 13px;
                  cursor: pointer;
                  display: inline-flex;
                  align-items: center;
                  gap: 6px;
                  transition: all 0.2s;
                }
                .toolbar-btn:hover { background: #6d28d9; }
                .toolbar-btn-danger {
                  background: #475569;
                }
                .toolbar-btn-danger:hover { background: #334155; }
                @media print {
                  .toolbar-header { display: none !important; }
                  body { padding: 0 !important; }
                }
              </style>
            </head>
            <body>
              <div class="toolbar-header">
                <div style="display: flex; align-items: center; gap: 8px;">
                  <span style="font-size: 16px;">🛡️</span>
                  <strong style="font-size: 14px;">Báo Cáo An Ninh Active Directory: ${escapeHtml(domain)}</strong>
                  <span style="background: rgba(139, 92, 246, 0.2); color: #c4b5fd; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 8px;">Tệp PDF đã tự động tải về</span>
                </div>
                <div style="display: flex; gap: 10px;">
                  <button class="toolbar-btn" onclick="window.print()">
                    🖨️ In Báo Cáo / Lưu PDF Trình Duyệt
                  </button>
                  <button class="toolbar-btn toolbar-btn-danger" onclick="window.close()">
                    ✖️ Đóng
                  </button>
                </div>
              </div>
              <div style="padding: 24px; max-width: 900px; margin: 0 auto;">
                ${reportBodyHtml}
              </div>
            </body>
            </html>
          `;
          previewWindow.document.write(fullHtml);
          previewWindow.document.close();
        }
      } catch (winErr) {
        console.warn('Popup preview AD bị chặn:', winErr);
      }
    } catch (err) {
      console.error('Lỗi xuất báo cáo PDF AD:', err);
      toastEmitter.show('Lỗi', err?.message || 'Không thể tạo file PDF Active Directory.', 'error');
    } finally {
      setIsExportingPdf(false);
    }
  };

  // Lọc tìm kiếm và phân loại liên kết quyền theo tài khoản hoặc mức độ rủi ro (Hoạt động linh hoạt với mọi nguồn dữ liệu)
  const filteredFindings = useMemo(() => {
    if (!data?.highRiskFindings) return [];
    return data.highRiskFindings.filter(f => {
      if (riskFilter !== 'ALL' && f.riskLevel?.toUpperCase() !== riskFilter) {
        return false;
      }
      if (!findingFilter.trim()) return true;
      const q = findingFilter.trim().toLowerCase();
      return (
        (f.sourcePrincipal && f.sourcePrincipal.toLowerCase().includes(q)) ||
        (f.targetObject && f.targetObject.toLowerCase().includes(q)) ||
        (f.relationshipType && f.relationshipType.toLowerCase().includes(q)) ||
        (f.description && f.description.toLowerCase().includes(q)) ||
        (f.remediation && f.remediation.toLowerCase().includes(q))
      );
    });
  }, [data?.highRiskFindings, findingFilter, riskFilter]);

  return (
    <div className="card-panel" style={{ padding: '1.5rem', background: '#090e17', border: '1px solid #1e293b', borderRadius: '10px' }}>
      
      {/* Header Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem', borderBottom: '1px solid #1e293b', paddingBottom: '1.25rem', marginBottom: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div style={{ width: '42px', height: '42px', borderRadius: '10px', background: 'linear-gradient(135deg, #ef4444, #8b5cf6)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontSize: '1.25rem', boxShadow: '0 0 15px rgba(239, 68, 68, 0.4)' }}>
            <i className="fa-solid fa-diagram-project"></i>
          </div>
          <div>
            <div style={{ fontWeight: 800, color: '#f8fafc', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span>Kiểm Thử AD</span>
              <span className="cyber-pill-badge" style={{ fontSize: '0.72rem', background: 'rgba(16, 185, 129, 0.15)', color: '#6ee7b7', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                <span className="dot-live" style={{ background: '#10b981' }}></span> Live Active Directory
              </span>
            </div>
            <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              Xác thực Domain Controller, bóc tách ma trận quyền và phân tích chuỗi leo quyền AD
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
          <button
            type="button"
            className={`btn ${showConfigForm ? 'btn-purple' : 'btn-outline'}`}
            style={{ fontSize: '0.82rem', padding: '0.45rem 0.9rem', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
            onClick={() => setShowConfigForm(!showConfigForm)}
          >
            <i className={`fa-solid ${showConfigForm ? 'fa-eye-slash' : 'fa-sliders'}`}></i>
            <span>{showConfigForm ? 'Ẩn Form Nạp Dữ Liệu' : 'Mở Form Cấu Hình AD'}</span>
          </button>

          {data && (
            <button
              type="button"
              className="btn btn-outline"
              style={{ fontSize: '0.82rem', padding: '0.45rem 0.9rem', color: '#f87171', borderColor: 'rgba(239, 68, 68, 0.4)' }}
              onClick={() => {
                setData(null);
                setSelectedHistoryId('');
                setRawJsonText('');
                setShowConfigForm(true);
                try {
                  localStorage.removeItem('attt_bloodhound_audit_data');
                } catch (e) {}
                toastEmitter.show('Đã xóa', 'Đã chuyển về màn hình cấu hình quét mới.', 'info');
              }}
            >
              <i className="fa-solid fa-trash-can" style={{ marginRight: '0.35rem' }}></i>
              <span>Xóa Dữ Liệu</span>
            </button>
          )}

          {data && onAskAi && (
            <button
              type="button"
              className="btn btn-purple"
              style={{ fontSize: '0.82rem', padding: '0.45rem 0.95rem', display: 'inline-flex', alignItems: 'center', gap: '0.4rem', boxShadow: '0 0 12px rgba(168, 85, 247, 0.4)' }}
              onClick={() => {
                const targetDomain = data.domainName || data.domain || ldapConfig.domain || '';
                const targetHost = ldapConfig.host || data.target || data.host || '';
                const targetUser = ldapConfig.username || data.authenticatedUser || '';
                let targetPass = ldapConfig.password || '';
                if (!targetPass) {
                  try {
                    const cached = JSON.parse(localStorage.getItem('attt_bloodhound_audit_data') || '{}');
                    if (cached.authenticatedUser === targetUser || !targetUser) {
                      targetPass = cached.password || '';
                    }
                  } catch (e) {}
                }

                try {
                  localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
                    taskId: selectedHistoryId || data.taskId,
                    domain: targetDomain,
                    host: targetHost,
                    port: ldapConfig.port || 389,
                    authenticatedUser: targetUser,
                    password: targetPass,
                    hasValidCredentials: !!targetUser,
                    summary: data,
                    rawJson: rawJsonText,
                    scannedAt: new Date().toISOString()
                  }));
                } catch (e) {}

                onAskAi({
                  type: 'BLOODHOUND_SCAN',
                  domain: targetDomain,
                  host: targetHost,
                  username: targetUser,
                  password: targetPass,
                  bloodhoundData: {
                    ...data,
                    domainName: targetDomain,
                    host: targetHost,
                    authenticatedUser: targetUser,
                    password: targetPass
                  },
                  shortLabel: `Phân tích toàn bộ dữ liệu Active Directory thực tế ${targetDomain ? `(${targetDomain})` : ''} và hướng dẫn kịch bản kiểm thử BƯỚC 1`,
                  prompt: `Hãy phân tích chuyên sâu các kịch bản kiểm thử leo quyền trên Active Directory ${targetDomain} (DC: ${targetHost}). Tôi đã cung cấp thông tin mục tiêu và xác thực: Tên miền: "${targetDomain}", Máy chủ DC: "${targetHost}", Tài khoản: "${targetUser}"${targetPass ? `, Mật khẩu: "${targetPass}"` : ''}. BẮT BUỘC CHUẨN HÓA mọi câu lệnh kiểm thử, điền trực tiếp thông tin xác thực này vào các lệnh (như impacket-GetUserSPNs, ldapsearch, netexec...) thay vì dùng placeholder <domain>, <ip>, <username>, <password>. Hãy hướng dẫn tôi BƯỚC 1 theo quy trình tương tác từng bước một!`
                });
              }}
              title="Gửi dữ liệu Active Directory này sang Trợ Lý AI"
            >
              <i className="fa-solid fa-comments"></i>
              <span>Gửi Sang Trợ Lý AI</span>
            </button>
          )}

          {data && (
            <button
              type="button"
              className="btn btn-outline"
              style={{ fontSize: '0.82rem', padding: '0.45rem 0.95rem', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.45)', display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
              onClick={handleExportPdf}
              disabled={isExportingPdf}
              title="Tải tệp PDF báo cáo an ninh Active Directory về máy tính"
            >
              <i className={`fa-solid ${isExportingPdf ? 'fa-spinner fa-spin' : 'fa-file-pdf'}`}></i>
              <span>{isExportingPdf ? 'Đang Xuất PDF...' : 'Tải Báo Cáo PDF'}</span>
            </button>
          )}

          <input
            type="file"
            ref={fileInputRef}
            style={{ display: 'none' }}
            accept=".json"
            onChange={handleFileUpload}
          />
        </div>
      </div>

      {/* THANH ĐIỀU HƯỚNG LỊCH SỬ CÁC LẦN QUÉT ACTIVE DIRECTORY */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.85rem',
        padding: '0.75rem 1rem',
        marginBottom: '1.25rem',
        background: '#0d1527',
        border: '1px solid #1e293b',
        borderRadius: '8px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: '#38bdf8', fontSize: '0.86rem', fontWeight: 700 }}>
            <i className="fa-solid fa-clock-rotate-left"></i>
            <span>Lịch Sử Quét AD (Database):</span>
          </div>

          {loadingHistory ? (
            <span style={{ fontSize: '0.8rem', color: '#94a3b8', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
              <i className="fa-solid fa-spinner fa-spin"></i> Đang tải danh sách các lần quét...
            </span>
          ) : scanHistory.length > 0 ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <select
                value={selectedHistoryId ? String(selectedHistoryId) : ''}
                onChange={(e) => {
                  const val = e.target.value;
                  if (!val) {
                    setSelectedHistoryId('');
                    setData(null);
                    setRawJsonText('');
                    setShowConfigForm(true);
                    try {
                      localStorage.removeItem('attt_bloodhound_audit_data');
                    } catch (err) {}
                  } else {
                    const found = scanHistory.find(h => String(h.taskId) === String(val));
                    if (found) selectHistoryItem(found, true);
                  }
                }}
                className="form-control"
                style={{
                  fontSize: '0.82rem',
                  padding: '0.4rem 0.8rem',
                  background: '#090e17',
                  border: '1px solid #38bdf8',
                  color: '#f8fafc',
                  borderRadius: '6px',
                  minWidth: '290px',
                  cursor: 'pointer',
                  fontWeight: 600
                }}
              >
                <option value="">+ Quét Mới / Nhập Cấu Hình AD Mới</option>
                {scanHistory.map(h => {
                  const totalObj = h.totalObjects || h.summary?.totalObjectsScanned || h.summary?.totalObjects || 0;
                  const highRisks = h.highRiskCount || h.summary?.highRiskFindings?.length || ((h.summary?.criticalRiskCount || 0) + (h.summary?.highRiskCount || 0)) || 0;
                  const domain = h.domain || h.summary?.domainName || h.target || 'Active Directory';
                  return (
                    <option key={h.taskId} value={String(h.taskId)}>
                      {domain} ({totalObj} đối tượng, {highRisks} ACL rủi ro) - {h.createdAt ? new Date(h.createdAt).toLocaleDateString('vi-VN') + ' ' + new Date(h.createdAt).toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit' }) : ''}
                    </option>
                  );
                })}
              </select>

              <button
                type="button"
                onClick={() => loadHistory(false)}
                className="btn btn-outline"
                title="Làm mới danh sách lần quét"
                style={{ padding: '0.38rem 0.65rem', fontSize: '0.8rem', color: '#38bdf8', borderColor: 'rgba(56, 189, 248, 0.4)' }}
              >
                <i className="fa-solid fa-arrows-rotate"></i>
              </button>

              {selectedHistoryId && (
                <button
                  type="button"
                  onClick={handleDeleteCurrentHistory}
                  className="btn btn-outline"
                  title="Xóa lần quét này khỏi cơ sở dữ liệu"
                  style={{ padding: '0.38rem 0.65rem', fontSize: '0.8rem', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.4)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                >
                  <i className="fa-solid fa-trash-can"></i>
                  <span>Xóa lần này</span>
                </button>
              )}

              {data && (
                <button
                  type="button"
                  onClick={handleExportPdf}
                  disabled={isExportingPdf}
                  className="btn btn-outline"
                  title="Xuất lần quét này thành tệp PDF"
                  style={{ padding: '0.38rem 0.65rem', fontSize: '0.8rem', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.4)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
                >
                  <i className={`fa-solid ${isExportingPdf ? 'fa-spinner fa-spin' : 'fa-file-pdf'}`}></i>
                  <span>{isExportingPdf ? 'Đang xuất...' : 'Xuất PDF'}</span>
                </button>
              )}

              <button
                type="button"
                onClick={handleDeleteAllHistory}
                className="btn btn-outline"
                title="Xóa toàn bộ lịch sử các lần quét cũ"
                style={{ padding: '0.38rem 0.65rem', fontSize: '0.8rem', color: '#f87171', borderColor: 'rgba(239, 68, 68, 0.3)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
              >
                <i className="fa-solid fa-broom"></i>
                <span>Dọn sạch lịch sử</span>
              </button>
            </div>
          ) : (
            <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
              Chưa có lần quét AD nào được lưu trong Database. Vui lòng quét qua form bên dưới.
            </span>
          )}
        </div>

        {data && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem' }}>
            <span style={{ color: '#94a3b8' }}>Đang xem:</span>
            <span className="cyber-pill-badge" style={{ background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', border: '1px solid rgba(56, 189, 248, 0.3)', fontWeight: 700 }}>
              {selectedHistoryId ? 'Bản ghi lịch sử' : 'Phiên hiện tại'} • DC: {data?.domainName || data?.domain || ldapConfig.domain || '(chưa xác định)'} ({ldapConfig.host || '(chưa xác định)'})
            </span>
          </div>
        )}
      </div>

      {/* FORM NHẬP THÔNG TIN KẾT NỐI (BẮT BUỘC TÀI KHOẢN VÀ DOMAIN RIÊNG BIỆT - KHÔNG MOCK) */}
      {showConfigForm && (
        <div style={{ background: '#0b1324', border: '1px solid #334155', borderRadius: '10px', padding: '1.25rem', marginBottom: '1.5rem', boxShadow: '0 4px 20px rgba(0,0,0,0.5)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <i className="fa-solid fa-shield-halved" style={{ color: '#38bdf8' }}></i>
              <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.95rem' }}>
                Cấu Hình Xác Thực Active Directory
              </span>
            </div>
            <div style={{ fontSize: '0.78rem', color: '#94a3b8' }}>
              Chọn phương thức xác thực hoặc nạp tệp bên dưới:
            </div>
          </div>

          {/* Chọn Chế Độ Nạp */}
          <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
            <button
              type="button"
              className={`btn btn-sm ${inputMode === 'ldap' ? 'btn-purple' : 'btn-outline'}`}
              onClick={() => setInputMode('ldap')}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <i className="fa-solid fa-network-wired"></i>
              <span>1. Kết Nối Trực Tiếp Active Directory</span>
            </button>

            <button
              type="button"
              className={`btn btn-sm ${inputMode === 'upload' ? 'btn-purple' : 'btn-outline'}`}
              onClick={() => setInputMode('upload')}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <i className="fa-solid fa-file-arrow-up"></i>
              <span>2. Tải Lên Tệp BloodHound JSON</span>
            </button>

            <button
              type="button"
              className={`btn btn-sm ${inputMode === 'paste' ? 'btn-purple' : 'btn-outline'}`}
              onClick={() => setInputMode('paste')}
              style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
            >
              <i className="fa-solid fa-paste"></i>
              <span>3. Dán Nội Dung JSON BloodHound</span>
            </button>
          </div>

          {/* PHƯƠNG THỨC 1: KẾT NỐI LDAP */}
          {inputMode === 'ldap' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Tên Miền Active Directory: <span style={{ color: '#ef4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="ví dụ: corp.contoso.com hoặc attt.local"
                    value={ldapConfig.domain}
                    onChange={(e) => handleDomainChange(e.target.value)}
                  />
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>Tên miền AD cần thu thập đồ thị phân quyền.</div>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Địa Chỉ Domain Controller: <span style={{ color: '#ef4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="ví dụ: 192.168.1.100 hoặc dc01.corp.contoso.com"
                    value={ldapConfig.host}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, host: e.target.value })}
                  />
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>IP hoặc Hostname của Domain Controller.</div>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Tài Khoản AD: <span style={{ color: '#ef4444' }}>*</span>
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="ví dụ: attacker hoặc tài khoản miền"
                    value={ldapConfig.username}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, username: e.target.value })}
                  />
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>Tên tài khoản miền.</div>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Mật Khẩu Tài Khoản: <span style={{ color: '#ef4444' }}>*</span>
                  </label>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showPassword ? 'text' : 'password'}
                      className="form-control"
                      placeholder="Nhập mật khẩu tài khoản AD"
                      value={ldapConfig.password}
                      style={{ paddingRight: '2.5rem' }}
                      onChange={(e) => setLdapConfig({ ...ldapConfig, password: e.target.value })}
                    />
                    <button
                      type="button"
                      style={{ position: 'absolute', right: '0.5rem', top: '50%', transform: 'translateY(-50%)', background: 'transparent', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '0.25rem' }}
                      onClick={() => setShowPassword(!showPassword)}
                      title={showPassword ? 'Ẩn mật khẩu' : 'Hiện mật khẩu'}
                    >
                      <i className={`fa-solid ${showPassword ? 'fa-eye-slash' : 'fa-eye'}`}></i>
                    </button>
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>Dùng để Simple Bind vào LDAP máy chủ DC.</div>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Cổng Dịch Vụ LDAP: <span style={{ color: '#ef4444' }}>*</span>
                  </label>
                  <input
                    type="number"
                    className="form-control"
                    placeholder="389 hoặc 636"
                    value={ldapConfig.port}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, port: e.target.value })}
                  />
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.78rem', color: '#cbd5e1', marginBottom: '0.35rem', fontWeight: 600 }}>
                    Base DN:
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    placeholder="ví dụ: DC=corp,DC=contoso,DC=com"
                    value={ldapConfig.baseDn}
                    onChange={(e) => setLdapConfig({ ...ldapConfig, baseDn: e.target.value })}
                  />
                  <div style={{ fontSize: '0.7rem', color: '#64748b', marginTop: '0.2rem' }}>Mặc định tự động điền theo domain, có thể chỉ định OU cụ thể.</div>
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem', borderTop: '1px solid #1e293b', paddingTop: '1rem' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.82rem', color: '#cbd5e1' }}>
                  <input
                    type="checkbox"
                    checked={ldapConfig.useSsl}
                    onChange={(e) => {
                      const checked = e.target.checked;
                      setLdapConfig({
                        ...ldapConfig,
                        useSsl: checked,
                        port: checked ? (ldapConfig.port === '389' ? '636' : ldapConfig.port) : (ldapConfig.port === '636' ? '389' : ldapConfig.port)
                      });
                    }}
                  />
                  <span>Sử dụng mã hóa LDAPS</span>
                </label>

                <button
                  type="button"
                  className="btn btn-purple"
                  style={{ padding: '0.55rem 1.6rem', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
                  onClick={handleConnectAndScan}
                  disabled={loading}
                >
                  <i className={`fa-solid ${loading ? 'fa-spinner fa-spin' : 'fa-plug-circle-check'}`}></i>
                  <span>{loading ? 'Đang Xác Thực & Thu Thập...' : 'Xác Thực & Thu Thập Dữ Liệu AD'}</span>
                </button>
              </div>
            </div>
          )}

          {/* PHƯƠNG THỨC 2: UPLOAD FILE JSON SHARPHOUND THẬT */}
          {inputMode === 'upload' && (
            <div style={{ textAlign: 'center', padding: '2.5rem 1.5rem', border: '2px dashed #334155', borderRadius: '8px', background: '#070b14' }}>
              <i className="fa-solid fa-file-arrow-up" style={{ fontSize: '2.5rem', color: '#a855f7', marginBottom: '1rem' }}></i>
              <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.75rem' }}>
                Tải lên tệp JSON SharpHound hoặc BloodHound.py
              </div>

              <button
                type="button"
                className="btn btn-purple"
                style={{ padding: '0.6rem 1.6rem', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
                onClick={() => fileInputRef.current?.click()}
                disabled={loading}
              >
                <i className={`fa-solid ${loading ? 'fa-spinner fa-spin' : 'fa-folder-open'}`}></i>
                <span>{loading ? 'Đang Đọc & Phân Tích...' : 'Chọn Tệp SharpHound JSON Từ Máy Tính'}</span>
              </button>
            </div>
          )}

          {/* PHƯƠNG THỨC 3: DÁN MÃ JSON THỦ CÔNG */}
          {inputMode === 'paste' && (
            <div>
              <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                Dán toàn bộ nội dung JSON xuất từ SharpHound (chứa cấu trúc <code>data</code>, <code>Properties</code>, <code>Aces</code>):
              </div>
              <textarea
                className="form-control"
                rows="7"
                style={{ fontFamily: 'monospace', fontSize: '0.8rem', background: '#050811' }}
                placeholder='{ "data": [ { "Properties": { "name": "USER@DOMAIN.LOCAL", "admincount": true, "hasspn": true }, "Aces": [] } ] }'
                value={pasteJsonInput}
                onChange={(e) => setPasteJsonInput(e.target.value)}
              />
              <div style={{ marginTop: '0.85rem', textAlign: 'right' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  style={{ padding: '0.55rem 1.4rem', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: '0.5rem' }}
                  onClick={handlePasteJsonSubmit}
                  disabled={loading || !pasteJsonInput.trim()}
                >
                  <i className={`fa-solid ${loading ? 'fa-spinner fa-spin' : 'fa-brain'}`}></i>
                  <span>{loading ? 'Đang Phân Tích...' : 'Phân Tích Dữ Liệu JSON Vừa Dán'}</span>
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* THỐNG KÊ MA TRẬN & BÁO CÁO */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <div style={{ background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem 1.1rem' }}>
          <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Đối Tượng Đã Phân Tích</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#38bdf8', marginTop: '0.2rem' }}>
            {data?.totalObjectsScanned || 0} Đối tượng
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b' }}>Domain: {data?.domainName || ldapConfig.domain || 'N/A'}</div>
        </div>

        <div style={{ background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem 1.1rem' }}>
          <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Ma Trận Quyền Rủi Ro</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: (data?.criticalRiskCount || 0) > 0 ? '#ef4444' : '#34d399', marginTop: '0.2rem' }}>
            {(data?.criticalRiskCount || 0) + (data?.highRiskCount || 0)} ACLs Nguy Cấp
          </div>
          <div style={{ fontSize: '0.72rem', color: '#ef4444' }}>{data?.criticalRiskCount || 0} Critical • {data?.highRiskCount || 0} High</div>
        </div>

        <div style={{ background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '0.85rem 1.1rem' }}>
          <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Báo Cáo Phân Tích</div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: data?.aiAnalysis ? '#10b981' : '#64748b', marginTop: '0.2rem' }}>
            {data?.aiAnalysis ? 'Đã Có Báo Cáo' : 'Chưa Phân Tích'}
          </div>
          <div style={{ fontSize: '0.72rem', color: data?.aiAnalysis ? '#34d399' : '#64748b' }}>AI Security Report</div>
        </div>
      </div>

      {/* Điều hướng 2 Tab duy nhất: Ma Trận và Báo Cáo */}
      <div style={{ display: 'flex', gap: '0.5rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem', marginBottom: '1.25rem', overflowX: 'auto' }}>
        <button
          className={`btn btn-sm ${activeSubTab === 'findings' ? 'btn-purple' : 'btn-outline'}`}
          onClick={() => setActiveSubTab('findings')}
        >
          <i className="fa-solid fa-table-cells"></i>
          <span>Ma Trận Quyền Nguy Cấp</span>
        </button>

        <button
          className={`btn btn-sm ${activeSubTab === 'ai' ? 'btn-purple' : 'btn-outline'}`}
          onClick={() => setActiveSubTab('ai')}
        >
          <i className="fa-solid fa-file-waveform"></i>
          <span>Báo Cáo Phân Tích AI {data?.aiAnalysis ? '✓' : ''}</span>
        </button>
      </div>

      {/* Khi chưa nạp dữ liệu */}
      {!data && (
        <div style={{ background: '#0c1322', border: '1px dashed #334155', borderRadius: '8px', padding: '2rem 1.5rem', textAlign: 'center', color: '#94a3b8' }}>
          <i className="fa-solid fa-shield-halved" style={{ fontSize: '2rem', color: '#38bdf8', marginBottom: '0.75rem' }}></i>
          <div style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.3rem' }}>
            Chưa Có Dữ Liệu Kiểm Thử AD
          </div>
          <div style={{ fontSize: '0.8rem', color: '#94a3b8', maxWidth: '480px', margin: '0 auto 1rem auto' }}>
            Vui lòng nhập thông tin kết nối AD ở trên hoặc tải lên tệp SharpHound JSON để xem ma trận quyền và nhận báo cáo phân tích.
          </div>
          {!showConfigForm && (
            <button
              type="button"
              className="btn btn-purple"
              onClick={() => setShowConfigForm(true)}
            >
              <i className="fa-solid fa-sliders" style={{ marginRight: '0.4rem' }}></i>
              <span>Mở Form Cấu Hình AD</span>
            </button>
          )}
        </div>
      )}

      {/* Content Panels KHI ĐÃ CÓ DỮ LIỆU */}
      {data && activeSubTab === 'ai' && (
        <div style={{ background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <i className="fa-solid fa-brain" style={{ color: '#a855f7', fontSize: '1.2rem' }}></i>
              <span style={{ fontWeight: 700, color: '#f8fafc', fontSize: '1rem' }}>
                Đánh Giá An Ninh & Chuỗi Leo Quyền Active Directory Bằng AI
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              {!data?.aiAnalysis && (
                <button
                  type="button"
                  className="btn btn-sm btn-purple"
                  onClick={handleAiAnalyze}
                  disabled={aiAnalyzing || !rawJsonText}
                >
                  <i className={`fa-solid ${aiAnalyzing ? 'fa-spinner fa-spin' : 'fa-wand-magic-sparkles'}`}></i>
                  <span>Phân Tích Ngay</span>
                </button>
              )}
              <button
                type="button"
                className="btn btn-sm btn-outline"
                onClick={handleExportPdf}
                disabled={isExportingPdf}
                title="Tải tệp PDF báo cáo an ninh Active Directory về máy tính"
                style={{ color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.45)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}
              >
                <i className={`fa-solid ${isExportingPdf ? 'fa-spinner fa-spin' : 'fa-file-pdf'}`}></i>
                <span>{isExportingPdf ? 'Đang Xuất PDF...' : 'Tải Báo Cáo PDF'}</span>
              </button>
            </div>
          </div>

          {aiAnalyzing ? (
            <div style={{ textAlign: 'center', padding: '3rem', color: '#94a3b8' }}>
              <i className="fa-solid fa-spinner fa-spin" style={{ fontSize: '2rem', color: '#a855f7', marginBottom: '1rem' }}></i>
              <div style={{ fontWeight: 600, color: '#f1f5f9' }}>AI đang đọc đồ thị phân quyền và tính toán chuỗi leo thang đặc quyền AD...</div>
              <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '0.25rem' }}>Bóc tách các kỹ thuật Kerberoasting, AS-REP Roasting và nguy cơ leo quyền Domain Admins.</div>
            </div>
          ) : data?.aiAnalysis ? (
            <div>
              <FormattedAiText text={data.aiAnalysis} />
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2.5rem', color: '#94a3b8' }}>
              <div style={{ marginBottom: '1rem' }}>Chưa có báo cáo AI cho dữ liệu hiện tại.</div>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleAiAnalyze}
                disabled={aiAnalyzing || !rawJsonText}
              >
                <i className="fa-solid fa-bolt-lightning" style={{ marginRight: '0.4rem' }}></i>
                <span>Gửi Dữ Liệu Cho AI Phân Tích</span>
              </button>
            </div>
          )}
        </div>
      )}

      {data && activeSubTab === 'findings' && (
        <div>
          {/* THANH CÔNG CỤ TÌM KIẾM & TRUY VẾT LIÊN KẾT QUYỀN GIỮA CÁC TÀI KHOẢN */}
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexWrap: 'wrap',
            gap: '0.75rem',
            background: '#0c1322',
            border: '1px solid #1e293b',
            borderRadius: '8px',
            padding: '0.75rem 1rem',
            marginBottom: '1rem'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flex: 1, minWidth: '260px' }}>
              <i className="fa-solid fa-magnifying-glass" style={{ color: '#64748b', fontSize: '0.9rem' }}></i>
              <input
                type="text"
                className="form-control"
                placeholder="Tra cứu tài khoản (VD: attacker, admin_target...) hoặc loại quyền..."
                value={findingFilter}
                onChange={e => setFindingFilter(e.target.value)}
                style={{
                  fontSize: '0.84rem',
                  background: '#090e17',
                  border: '1px solid #334155',
                  color: '#f8fafc',
                  padding: '0.4rem 0.75rem',
                  borderRadius: '6px',
                  width: '100%'
                }}
              />
              {findingFilter && (
                <button
                  type="button"
                  className="btn btn-sm btn-outline"
                  onClick={() => setFindingFilter('')}
                  title="Xóa bộ lọc tìm kiếm"
                  style={{ fontSize: '0.75rem', padding: '0.35rem 0.6rem', color: '#94a3b8' }}
                >
                  <i className="fa-solid fa-xmark"></i>
                </button>
              )}
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                className={`btn btn-sm ${riskFilter === 'ALL' ? 'btn-primary' : 'btn-outline'}`}
                style={{ fontSize: '0.76rem', padding: '0.35rem 0.7rem' }}
                onClick={() => setRiskFilter('ALL')}
              >
                Tất Cả ({data?.highRiskFindings?.length || 0})
              </button>
              <button
                type="button"
                className={`btn btn-sm ${riskFilter === 'CRITICAL' ? 'btn-danger' : 'btn-outline'}`}
                style={{ fontSize: '0.76rem', padding: '0.35rem 0.7rem' }}
                onClick={() => setRiskFilter('CRITICAL')}
              >
                CRITICAL ({data?.criticalRiskCount || 0})
              </button>
              <button
                type="button"
                className={`btn btn-sm ${riskFilter === 'HIGH' ? 'btn-warning' : 'btn-outline'}`}
                style={{ fontSize: '0.76rem', padding: '0.35rem 0.7rem' }}
                onClick={() => setRiskFilter('HIGH')}
              >
                HIGH ({data?.highRiskCount || 0})
              </button>

              <button
                type="button"
                className="btn btn-sm btn-outline"
                style={{ fontSize: '0.76rem', padding: '0.35rem 0.75rem', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.45)', display: 'inline-flex', alignItems: 'center', gap: '0.35rem', marginLeft: '0.35rem' }}
                onClick={handleExportPdf}
                disabled={isExportingPdf}
                title="Tải tệp PDF ma trận quyền Active Directory về máy tính"
              >
                <i className={`fa-solid ${isExportingPdf ? 'fa-spinner fa-spin' : 'fa-file-pdf'}`}></i>
                <span>{isExportingPdf ? 'Đang Xuất...' : 'Xuất PDF'}</span>
              </button>
            </div>
          </div>

          {/* CHỈ BÁO KHI ĐANG LỌC THEO TÀI KHOẢN CỤ THỂ */}
          {findingFilter && (
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'rgba(59, 130, 246, 0.08)',
              border: '1px solid rgba(59, 130, 246, 0.3)',
              borderRadius: '6px',
              padding: '0.55rem 0.85rem',
              marginBottom: '1rem',
              fontSize: '0.82rem',
              color: '#93c5fd'
            }}>
              <div>
                <i className="fa-solid fa-filter" style={{ marginRight: '0.45rem', color: '#60a5fa' }}></i>
                Đang lọc quan hệ liên quan đến: <strong style={{ color: '#fff' }}>"{findingFilter}"</strong> (Tìm thấy {filteredFindings.length} liên kết)
              </div>
              <button
                type="button"
                className="btn btn-sm btn-outline"
                style={{ fontSize: '0.72rem', padding: '0.2rem 0.55rem', color: '#cbd5e1' }}
                onClick={() => setFindingFilter('')}
              >
                Xem Toàn Bộ
              </button>
            </div>
          )}

          {/* DANH SÁCH CÁC LIÊN KẾT NGUY CƠ CAO */}
          {filteredFindings && filteredFindings.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {filteredFindings.map((f, idx) => (
                <div key={idx} style={{
                  background: '#0c1322',
                  border: '1px solid #1e293b',
                  borderLeft: f.riskLevel === 'CRITICAL' ? '4px solid #ef4444' : '4px solid #f59e0b',
                  borderRadius: '0 8px 8px 0',
                  padding: '1rem 1.25rem'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '0.5rem' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                      <span className={`pill-vuln ${f.riskLevel?.toLowerCase()}`}>
                        {f.riskLevel}
                      </span>

                      {/* TÀI KHOẢN NGUỒN - CÓ THỂ NHẤP ĐỂ LỌC TRUY VẾT */}
                      <span
                        onClick={() => setFindingFilter(f.sourcePrincipal)}
                        title={`Nhấp để lọc toàn bộ liên kết của "${f.sourcePrincipal}"`}
                        style={{
                          fontWeight: 700,
                          color: '#93c5fd',
                          background: 'rgba(59, 130, 246, 0.12)',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          fontSize: '0.88rem',
                          border: '1px solid rgba(59, 130, 246, 0.25)',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        {f.sourcePrincipal}
                      </span>

                      <span style={{ color: '#ef4444', fontWeight: 800, fontSize: '0.9rem' }}>
                        ➔ [{f.relationshipType}] ➔
                      </span>

                      {/* ĐỐI TƯỢNG ĐÍCH - CÓ THỂ NHẤP ĐỂ LỌC TIẾP */}
                      <span
                        onClick={() => setFindingFilter(f.targetObject)}
                        title={`Nhấp để lọc toàn bộ liên kết của đối tượng "${f.targetObject}"`}
                        style={{
                          fontWeight: 700,
                          color: '#fde047',
                          background: 'rgba(234, 179, 8, 0.12)',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          cursor: 'pointer',
                          fontSize: '0.88rem',
                          border: '1px solid rgba(234, 179, 8, 0.25)',
                          transition: 'all 0.15s ease'
                        }}
                      >
                        {f.targetObject}
                      </span>
                    </div>

                    {onAskAi && (
                      <button
                        type="button"
                        className="btn btn-sm btn-purple"
                        style={{ fontSize: '0.74rem', padding: '0.25rem 0.65rem' }}
                        onClick={() => {
                          const targetDomain = data?.domainName || data?.domain || ldapConfig.domain || '';
                          const targetHost = ldapConfig.host || data?.target || data?.host || '';
                          const targetUser = ldapConfig.username || data?.authenticatedUser || '';
                          let targetPass = ldapConfig.password || '';
                          if (!targetPass) {
                            try {
                              const cached = JSON.parse(localStorage.getItem('attt_bloodhound_audit_data') || '{}');
                              if (cached.authenticatedUser === targetUser || !targetUser) {
                                targetPass = cached.password || '';
                              }
                            } catch (e) {}
                          }
                          onAskAi({
                            domain: targetDomain,
                            host: targetHost,
                            username: targetUser,
                            password: targetPass,
                            bloodhoundData: data,
                            finding: f,
                            shortLabel: `Tư vấn khắc phục liên kết quyền: ${f.sourcePrincipal} ➔ [${f.relationshipType}] ➔ ${f.targetObject}`,
                            prompt: `Hướng dẫn phân tích rủi ro an ninh và các bước khắc phục bảo mật (AD Hardening) cho liên kết quyền: "${f.sourcePrincipal}" có quyền "${f.relationshipType}" trên "${f.targetObject}". Thông tin mục tiêu: Tên miền: "${targetDomain}", Máy chủ DC: "${targetHost}", Tài khoản: "${targetUser}"${targetPass ? `, Mật khẩu: "${targetPass}"` : ''}. BẮT BUỘC CHUẨN HÓA mọi câu lệnh kiểm thử, điền trực tiếp thông tin xác thực này thay vì dùng placeholder.`
                          });
                        }}
                      >
                        <i className="fa-solid fa-shield-halved"></i> Tư Vấn Khắc Phục AI
                      </button>
                    )}
                  </div>

                  <div style={{ fontSize: '0.82rem', color: '#cbd5e1', marginBottom: '0.4rem' }}>
                    <strong>Mô tả:</strong> {f.description}
                  </div>

                  <div style={{ fontSize: '0.78rem', color: '#34d399', background: 'rgba(16, 185, 129, 0.08)', padding: '0.4rem 0.65rem', borderRadius: '4px' }}>
                    <strong>Khuyến nghị khắc phục:</strong> {f.remediation}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '2.5rem', color: '#94a3b8', background: '#0c1322', borderRadius: '8px', border: '1px solid #1e293b' }}>
              <i className="fa-solid fa-circle-check" style={{ fontSize: '1.8rem', color: '#38bdf8', marginBottom: '0.6rem', display: 'block' }}></i>
              {findingFilter
                ? `Không tìm thấy liên kết quyền nào khớp với từ khóa "${findingFilter}".`
                : 'Không phát hiện liên kết quyền nguy hiểm nào trong dữ liệu hiện tại.'}
              {findingFilter && (
                <div style={{ marginTop: '0.75rem' }}>
                  <button
                    type="button"
                    className="btn btn-sm btn-outline"
                    onClick={() => { setFindingFilter(''); setRiskFilter('ALL'); }}
                  >
                    Xóa Bộ Lọc
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Kết thúc các tab */}
    </div>
  );
}
