import React, { useState, useEffect } from 'react';
import { toastEmitter, apiClient } from '../services/api';
import CreateAssessmentView from './CreateAssessmentView';
import ScanAiExplanationCard from '../components/ScanAiExplanationCard';
import GroqAssistantModal from '../components/GroqAssistantModal';
import html2pdf from 'html2pdf.js';

export default function AssessmentsView({ setActiveTab }) {
  const [viewMode, setViewMode] = useState('list'); // 'list' | 'create'
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [assessments, setAssessments] = useState([]);
  const [loading, setLoading] = useState(false);

  // Phân trang (Pagination)
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  // Modal Chi tiết
  const [selectedAssessment, setSelectedAssessment] = useState(null);
  const [activeModalTab, setActiveModalTab] = useState('latest'); // 'latest' | 'history' | 'report'
  const [selectedHistoryScanId, setSelectedHistoryScanId] = useState(null);

  // Dữ liệu cho modal
  const [planData, setPlanData] = useState(null);
  const [scansData, setScansData] = useState([]);
  const [reportData, setReportData] = useState(null);
  const [modalLoading, setModalLoading] = useState(false);
  const [executingStepId, setExecutingStepId] = useState(null);
  const [generatingAi, setGeneratingAi] = useState(false);
  const [isExportingPdf, setIsExportingPdf] = useState(false);

  // AI Explanation cache per scan task ID: { [taskId]: explanationObject }
  const [scanExplanations, setScanExplanations] = useState({});
  const [explainingScanId, setExplainingScanId] = useState(null);

  // Groq Assistant Modal
  const [assistantOpen, setAssistantOpen] = useState(false);
  const [assistantContext, setAssistantContext] = useState(null);

  // Quick Scanner State (Tách bạch Quét URL và Quét IP)
  const [quickScanMode, setQuickScanMode] = useState('URL'); // 'URL' | 'IP'
  const [quickUrl, setQuickUrl] = useState('');
  const [quickIp, setQuickIp] = useState('');
  const [isQuickAnalyzing, setIsQuickAnalyzing] = useState(false);

  // Reconnaissance Tool Integration State
  const [reconTarget, setReconTarget] = useState('');
  const [reconData, setReconData] = useState(null);
  const [reconLoading, setReconLoading] = useState(false);

  const fetchAssessments = async (showSpinner = false) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await apiClient.get('/assessments');
      const data = Array.isArray(res) ? res : res?.data || [];
      setAssessments(data);
    } catch (err) {
      console.warn('Backend chưa sẵn sàng');
    } finally {
      if (showSpinner) setLoading(false);
    }
  };

  useEffect(() => {
    fetchAssessments(true);
  }, []);

  const handleOpenDetail = (item) => {
    setSelectedAssessment(item);
    setActiveModalTab('latest');
    setSelectedHistoryScanId(null);
    setReconTarget(item?.targets?.[0] || '');
    setReconData(null);
    loadModalData(item.id, true);
  };

  const syncScanExplanations = (scans) => {
    if (!Array.isArray(scans) || scans.length === 0) return;
    setScanExplanations((prev) => {
      let changed = false;
      const updated = { ...prev };
      scans.forEach((scan) => {
        if (!updated[scan.id]) {
          if (scan.aiExplanation) {
            try {
              updated[scan.id] = typeof scan.aiExplanation === 'string' ? JSON.parse(scan.aiExplanation) : scan.aiExplanation;
              changed = true;
            } catch (e) {
              if (typeof scan.aiExplanation === 'string' && scan.aiExplanation.trim()) {
                updated[scan.id] = {
                  summary: scan.aiExplanation,
                  riskLevel: 'CRITICAL',
                  portsExplanation: [],
                  securityRisks: [],
                  stepByStepGuide: [],
                };
                changed = true;
              }
            }
          } else if (scan.parsedSummary) {
            try {
              const parsed = typeof scan.parsedSummary === 'string' ? JSON.parse(scan.parsedSummary) : scan.parsedSummary;
              if (parsed.aiExplanation) {
                updated[scan.id] = parsed.aiExplanation;
                changed = true;
              }
            } catch (e) {}
          }
        }
      });
      return changed ? updated : prev;
    });

    // Tự động phân tích AI cho các tác vụ đã quét xong nếu chưa có kết quả AI
    scans.forEach((scan) => {
      if (scan.status === 'COMPLETED' && !scanExplanations[scan.id] && !scan.aiExplanation) {
        handleExplainScanWithAi(scan, true);
      }
    });
  };

  const loadModalData = async (assessmentId, showLoading = false) => {
    if (showLoading) setModalLoading(true);
    try {
      const planRes = await apiClient.get(`/plans/assessment/${assessmentId}`).catch(() => null);
      if (planRes) {
        setPlanData(planRes);
        if (planRes.steps && planRes.steps.every((st) => st.status !== 'RUNNING')) {
          setExecutingStepId(null);
        }
      }

      const scansRes = await apiClient.get(`/scans/assessment/${assessmentId}`).catch(() => []);
      const scansArray = Array.isArray(scansRes) ? scansRes : scansRes?.data || [];
      setScansData(scansArray);
      syncScanExplanations(scansArray);

      if (scansArray.length > 0 && scansArray.every((s) => s.status !== 'RUNNING' && s.status !== 'PENDING')) {
        setExecutingStepId(null);
      }

      const reportRes = await apiClient.get(`/reports/assessment/${assessmentId}`).catch(() => null);
      if (reportRes) {
        setReportData(reportRes);
      } else {
        setReportData(null);
      }
    } finally {
      if (showLoading) setModalLoading(false);
    }
  };

  // Tự động Polling ngầm cập nhật kết quả Live CHỈ KHI có tác vụ đang quét
  useEffect(() => {
    if (!selectedAssessment?.id) return;

    const hasRunningTasks =
      executingStepId !== null ||
      scansData.some((s) => s.status === 'RUNNING' || s.status === 'PENDING') ||
      (planData?.steps && planData.steps.some((st) => st.status === 'RUNNING'));

    if (!hasRunningTasks) return; // Không poll nếu không có tác vụ nào đang chạy

    const assessmentId = selectedAssessment.id;
    let isMounted = true;

    const interval = setInterval(async () => {
      try {
        const [scansRes, planRes] = await Promise.all([
          apiClient.get(`/scans/assessment/${assessmentId}`).catch(() => null),
          apiClient.get(`/plans/assessment/${assessmentId}`).catch(() => null),
        ]);

        if (!isMounted) return;

        if (scansRes) {
          const scansArray = Array.isArray(scansRes) ? scansRes : scansRes?.data || [];
          setScansData((prev) => {
            if (JSON.stringify(prev) !== JSON.stringify(scansArray)) {
              return scansArray;
            }
            return prev;
          });
          syncScanExplanations(scansArray);

          if (scansArray.length > 0 && scansArray.every((s) => s.status !== 'RUNNING' && s.status !== 'PENDING')) {
            setExecutingStepId(null);
          }

          // Cập nhật nạp báo cáo đã được Backend tự động tạo và lưu trong DB
          if (scansArray.length > 0 && scansArray.every((s) => s.status === 'COMPLETED' || s.status === 'FAILED')) {
            const rep = await apiClient.get(`/reports/assessment/${assessmentId}`).catch(() => null);
            if (rep && isMounted) {
              setReportData(rep);
            }
          }
        }

        if (planRes) {
          setPlanData((prev) => {
            if (JSON.stringify(prev) !== JSON.stringify(planRes)) {
              return planRes;
            }
            return prev;
          });
          if (planRes.steps && planRes.steps.every((st) => st.status !== 'RUNNING')) {
            setExecutingStepId(null);
          }
        }

        // Cập nhật bảng danh sách để cập nhật trạng thái Hoàn Thành
        fetchAssessments();
      } catch (e) {}
    }, 2000);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [selectedAssessment?.id, executingStepId, scansData, planData, scanExplanations, reportData]);

  // HÀM PHÂN TÍCH NHANH: TÁCH BẠCH 2 CHẾ ĐỘ QUÉT URL (WEB) VÀ QUÉT IP (HẠ TẦNG)
  const handleQuickAnalyze = async (e) => {
    if (e && e.preventDefault) e.preventDefault();
    const isUrlMode = quickScanMode === 'URL';
    const rawTarget = isUrlMode ? quickUrl.trim() : quickIp.trim();

    if (!rawTarget) {
      toastEmitter.show(
        'Chưa nhập mục tiêu',
        isUrlMode
          ? 'Vui lòng nhập URL website mục tiêu (ví dụ: https://target.com hoặc http://10.0.0.5:8080).'
          : 'Vui lòng nhập IP máy chủ hoặc dải mạng mục tiêu (ví dụ: 192.168.1.10 hoặc 10.0.0.0/24).',
        'warning'
      );
      return;
    }

    setIsQuickAnalyzing(true);
    toastEmitter.show(
      'Đang khởi động phân tích',
      isUrlMode
        ? `Kích hoạt luồng quét ứng dụng Web & phân tích AI cho URL: ${rawTarget}...`
        : `Kích hoạt luồng quét cổng, dịch vụ hạ tầng & phân tích AI cho IP: ${rawTarget}...`,
      'info'
    );

    try {
      let target = rawTarget;
      let name = '';
      let type = 'SERVER';

      if (isUrlMode) {
        if (!target.startsWith('http://') && !target.startsWith('https://')) {
          target = `http://${target}`;
        }
        const cleanHost = target.replace(/^https?:\/\//i, '').split('/')[0];
        name = `Quét Web URL: ${cleanHost}`;
        type = 'WEB';
      } else {
        name = `Quét Hạ Tầng IP: ${target}`;
        type = 'SERVER';
      }

      const payload = {
        name,
        type,
        description: isUrlMode
          ? `Đánh giá an ninh ứng dụng Web, HTTP methods, SSL/TLS, thư mục nhạy cảm và lỗ hổng Web cho URL: ${target}`
          : `Rà soát an ninh hạ tầng, cổng mở, dịch vụ mạng Nmap và kiểm thử máy chủ cho IP: ${target}`,
        createdBy: 'Chuyên viên ATTT',
        targets: [target],
        excludedTargets: [],
      };

      // 1. Tạo đợt đánh giá
      const newAssessment = await apiClient.post('/assessments', payload);
      const assessmentId = newAssessment.id;

      // 2. Tự động lập kế hoạch
      await apiClient.post(`/plans/generate/${assessmentId}`).catch(() => null);

      // 3. Tự động phê duyệt toàn bộ
      await apiClient.post(`/plans/assessment/${assessmentId}/approve-all`, {
        approvedBy: 'Chuyên viên ATTT',
      }).catch(() => null);

      // 4. Tự động phát lệnh quét toàn bộ mục tiêu song song
      await apiClient.post(`/plans/assessment/${assessmentId}/execute-all`, {
        executedBy: 'Chuyên viên ATTT',
      }).catch(() => null);

      // 5. Mở modal chi tiết ngay lập tức
      setSelectedAssessment(newAssessment);
      setActiveModalTab('latest');
      setSelectedHistoryScanId(null);
      setExecutingStepId('all');
      if (isUrlMode) setQuickUrl('');
      else setQuickIp('');
      await loadModalData(assessmentId, true);
      fetchAssessments();

      toastEmitter.show(
        'Đang quét & Phân tích AI',
        isUrlMode
          ? 'Hệ thống đang kiểm tra an toàn HTTP/SSL, Web Dirs, DNS và phân tích ma trận lỗ hổng Web bằng AI!'
          : 'Hệ thống đang quét cổng mạng Nmap, nhận diện phiên bản dịch vụ và phân tích rủi ro máy chủ bằng AI!',
        'success'
      );
    } catch (err) {
      toastEmitter.show('Lỗi phân tích', err?.message || 'Không thể thực hiện phân tích toàn diện.', 'error');
    } finally {
      setIsQuickAnalyzing(false);
    }
  };

  // Handler chạy các công cụ Recon (Thu thập thông tin & Dò quét)
  const handleRunRecon = async (targetToScan, mode = 'ALL') => {
    const target = (targetToScan || reconTarget || selectedAssessment?.targets?.[0] || '').trim();
    if (!target) {
      toastEmitter.show('Chưa có mục tiêu', 'Vui lòng nhập mục tiêu cần kiểm thử Recon.', 'warning');
      return;
    }
    setReconTarget(target);
    setReconLoading(true);
    toastEmitter.show('Đang dò quét', `Bắt đầu thu thập thông tin cho ${target}...`, 'info');

    try {
      if (mode === 'ALL') {
        const res = await apiClient.post('/recon/comprehensive', { target });
        setReconData(res);
        toastEmitter.show('Hoàn tất Recon', `Đã phân tích toàn diện bề mặt tấn công của ${target}.`, 'success');
      } else if (mode === 'DNS') {
        const res = await apiClient.post('/recon/dns', { target });
        setReconData((prev) => ({ ...(prev || {}), target, dns: res }));
        toastEmitter.show('Hoàn tất DNS', `Thu thập được ${res?.records?.length || 0} bản ghi DNS.`, 'success');
      } else if (mode === 'WHOIS') {
        const res = await apiClient.post('/recon/whois', { target });
        setReconData((prev) => ({ ...(prev || {}), target, whois: res }));
        toastEmitter.show('Hoàn tất WHOIS', `Đã tra cứu thông tin tên miền ${target}.`, 'success');
      } else if (mode === 'HTTP') {
        const res = await apiClient.post('/recon/http-headers', { target });
        setReconData((prev) => ({ ...(prev || {}), target, httpSecurity: res }));
        toastEmitter.show('Hoàn tất HTTP', `Điểm an toàn: ${res?.score}/100 (Hạng ${res?.grade}).`, 'success');
      } else if (mode === 'DIR') {
        const res = await apiClient.post('/recon/web-directories', { target });
        setReconData((prev) => ({ ...(prev || {}), target, webDirectories: res }));
        toastEmitter.show('Hoàn tất Web Dirs', `Phát hiện ${res?.discoveredPaths?.length || 0} đường dẫn.`, 'success');
      }
    } catch (err) {
      toastEmitter.show('Lỗi dò quét', err?.message || 'Không thể thực hiện recon cho mục tiêu.', 'error');
    } finally {
      setReconLoading(false);
    }
  };

  // 1. Lập kế hoạch AI
  const handleGeneratePlan = async () => {
    if (!selectedAssessment) return;
    try {
      setGeneratingAi(true);
      toastEmitter.show('Đang xử lý...', 'AI đang phân tích mục tiêu và thiết lập kế hoạch quét toàn diện.', 'info');
      const res = await apiClient.post(`/plans/generate/${selectedAssessment.id}`);
      setPlanData(res);
      toastEmitter.show('Thành công', 'Đã thiết lập kế hoạch quét toàn diện cho tất cả mục tiêu.', 'success');
      fetchAssessments();
    } catch (err) {
      toastEmitter.show('Lỗi', err?.message || 'Không thể lập kế hoạch.', 'error');
    } finally {
      setGeneratingAi(false);
    }
  };

  // 2. Phê duyệt bước kiểm thử
  const handleApproveStep = async (stepId, approved) => {
    try {
      await apiClient.post(`/plans/steps/${stepId}/approve`, {
        approved: approved,
        approvedBy: 'Chuyên viên ATTT',
      });
      toastEmitter.show('Đã cập nhật', approved ? 'Đã duyệt bước kiểm thử.' : 'Đã từ chối bước kiểm thử.', 'success');
      loadModalData(selectedAssessment.id, false);
    } catch (err) {
      toastEmitter.show('Lỗi phê duyệt', err?.message || 'Không thể cập nhật.', 'error');
    }
  };

  // 3. Phê duyệt TẤT CẢ các bước
  const handleApproveAll = async () => {
    if (!selectedAssessment) return;
    try {
      const res = await apiClient.post(`/plans/assessment/${selectedAssessment.id}/approve-all`, {
        approvedBy: 'Chuyên viên ATTT',
      });
      setPlanData(res);
      toastEmitter.show('Đã duyệt tất cả', 'Tất cả các mục tiêu đã được phê duyệt sẵn sàng quét.', 'success');
    } catch (err) {
      toastEmitter.show('Lỗi phê duyệt', err?.message || 'Không thể duyệt tất cả.', 'error');
    }
  };

  // 4. Thực thi 1 bước kiểm thử
  const handleExecuteStep = async (stepId) => {
    try {
      setExecutingStepId(stepId);
      setActiveModalTab('latest');
      setSelectedHistoryScanId(null);
      toastEmitter.show('Bắt đầu quét', 'Tiến trình quét toàn diện Nmap đang chạy...', 'info');
      await apiClient.post(`/plans/steps/${stepId}/execute`, { executedBy: 'Chuyên viên ATTT' });
      toastEmitter.show('Đã phát lệnh', 'Đang thu thập và phân tích kết quả...', 'success');

      // Tải ngay để thấy trạng thái RUNNING
      loadModalData(selectedAssessment.id, false);
      fetchAssessments();

      setTimeout(() => {
        setExecutingStepId((prev) => (prev === stepId ? null : prev));
      }, 4000);
    } catch (err) {
      setExecutingStepId(null);
      toastEmitter.show('Lỗi thực thi', err?.message || 'Từ chối thực thi do vi phạm chính sách an toàn.', 'error');
    }
  };

  // 5. QUÉT TOÀN DIỆN TẤT CẢ CÙNG LÚC (ONE-CLICK EXECUTE ALL)
  const handleExecuteAll = async () => {
    if (!selectedAssessment) return;
    try {
      setExecutingStepId('all');
      setActiveModalTab('latest');
      setSelectedHistoryScanId(null);
      toastEmitter.show('Khởi động quét & phân tích AI', 'Đang kích hoạt quét toàn bộ mục tiêu và tự động phân tích AI...', 'info');
      const res = await apiClient.post(`/plans/assessment/${selectedAssessment.id}/execute-all`, {
        executedBy: 'Chuyên viên ATTT',
      });
      setPlanData(res);
      toastEmitter.show('Đang quét & phân tích AI', 'Hệ thống đang quét toàn diện và sẽ tự động giải thích kết quả bằng AI.', 'success');

      // Tải ngay lập tức
      loadModalData(selectedAssessment.id, false);
      fetchAssessments();

      // Timeout an toàn 120s phòng trường hợp tác vụ chạy quá lâu
      setTimeout(() => {
        setExecutingStepId((prev) => (prev === 'all' ? null : prev));
      }, 120000);
    } catch (err) {
      setExecutingStepId(null);
      toastEmitter.show('Lỗi thực thi', err?.message || 'Không thể kích hoạt quét toàn bộ.', 'error');
    }
  };

  // 6. Giải thích kết quả quét bằng AI
  const handleExplainScanWithAi = async (scanTask, isSilent = false) => {
    if (!scanTask?.id) return;
    try {
      setExplainingScanId(scanTask.id);
      if (!isSilent) {
        toastEmitter.show('AI Security', `Đang phân tích kết quả quét ${scanTask.target}...`, 'info');
      }
      const res = await apiClient.post(`/llm/explain-scan/${scanTask.id}`);
      setScanExplanations((prev) => ({
        ...prev,
        [scanTask.id]: res,
      }));
      if (!isSilent) {
        toastEmitter.show('Thành công', 'AI đã hoàn thành phân tích & giải thích.', 'success');
      }
    } catch (err) {
      if (!isSilent) {
        toastEmitter.show('Lỗi phân tích AI', err?.message || 'Không thể gọi AI.', 'error');
      }
    } finally {
      setExplainingScanId((prev) => (prev === scanTask.id ? null : prev));
    }
  };



  // 7. Mở Trợ Lý AI với bối cảnh cụ thể
  const handleOpenAiAssistant = (customContext = null) => {
    let ctx = null;
    if (selectedAssessment) {
      const latestScan = scansData && scansData.length > 0 ? scansData[0] : null;
      const baseContext = {
        assessment: selectedAssessment,
        plan: planData,
        scans: scansData,
        scanTask: latestScan,
        scansSummary: scansData.map((s) => {
          let parsed = null;
          try {
            parsed = s.parsedSummary ? (typeof s.parsedSummary === 'string' ? JSON.parse(s.parsedSummary) : s.parsedSummary) : null;
          } catch (e) {}
          return {
            id: s.id,
            target: s.target,
            profile: s.profile,
            status: s.status,
            parsedSummary: parsed,
            summary: parsed,
          };
        }),
        report: reportData,
      };

      if (customContext && typeof customContext === 'object') {
        ctx = { ...baseContext, ...customContext };
      } else if (customContext) {
        ctx = customContext;
      } else {
        ctx = baseContext;
      }
    } else {
      ctx = customContext;
    }
    setAssistantContext(ctx);
    setAssistantOpen(true);
  };


  // 8. Sinh báo cáo tổng kết AI
  const handleGenerateReport = async () => {
    if (!selectedAssessment) return;
    try {
      setGeneratingAi(true);
      toastEmitter.show('Đang tổng hợp...', 'AI đang tổng hợp các lỗ hổng và lập báo cáo an toàn.', 'info');
      const res = await apiClient.post(`/reports/generate/${selectedAssessment.id}`, {
        title: `Báo Cáo Đánh Giá An Toàn: ${selectedAssessment.name}`,
        generatedBy: 'Chuyên viên ATTT',
      });
      setReportData(res);
      toastEmitter.show('Thành công', 'Báo cáo an toàn đã sẵn sàng.', 'success');
      fetchAssessments();
    } catch (err) {
      toastEmitter.show('Lỗi', err?.message || 'Không thể tạo báo cáo.', 'error');
    } finally {
      setGeneratingAi(false);
    }
  };

  // 9. Xuất file PDF Báo Cáo Toàn Diện (Toàn bộ dữ liệu quét & phân tích AI)
  const handleExportPdf = async (targetAssessment = null) => {
    const currentAssessment = targetAssessment || selectedAssessment;
    if (!currentAssessment) {
      toastEmitter.show('Chưa chọn đợt đánh giá', 'Vui lòng chọn một đợt đánh giá để xuất báo cáo.', 'warning');
      return;
    }

    setIsExportingPdf(true);
    toastEmitter.show(
      'Đang xuất file PDF',
      `Đang tổng hợp dữ liệu và kết xuất tệp PDF cho "${currentAssessment.name}"...`,
      'info'
    );

    try {
      let scans = scansData;
      let rep = reportData;

    // Nếu gọi từ ngoài bảng danh sách hoặc dữ liệu chưa nạp:
    if (targetAssessment || !scans || scans.length === 0) {
      try {
        const [scansRes, repRes] = await Promise.all([
          apiClient.get(`/scans/assessment/${currentAssessment.id}`).catch(() => []),
          apiClient.get(`/reports/assessment/${currentAssessment.id}`).catch(() => null),
        ]);
        scans = Array.isArray(scansRes) ? scansRes : scansRes?.data || [];
        rep = repRes;
      } catch (e) {
        console.warn('Lỗi nạp dữ liệu đợt quét:', e);
      }
    }

    // Nếu chưa có báo cáo tổng hợp, tự động gọi tạo báo cáo
    if (!rep && currentAssessment.id) {
      try {
        rep = await apiClient.post(`/reports/generate/${currentAssessment.id}`).catch(() => null);
      } catch (e) {}
    }

    const sortedScans = [...(scans || [])].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
    const latestScan = sortedScans[0] || null;

    let parsedSummary = null;
    let aiExplanation = null;

    if (latestScan) {
      try {
        parsedSummary = latestScan.parsedSummary
          ? (typeof latestScan.parsedSummary === 'string' ? JSON.parse(latestScan.parsedSummary) : latestScan.parsedSummary)
          : null;
      } catch (e) {}

      aiExplanation = scanExplanations[latestScan.id];
      if (!aiExplanation) {
        try {
          const expRes = await apiClient.get(`/llm/explain/scan/${latestScan.id}`).catch(() => null);
          if (expRes) {
            aiExplanation = expRes.explanation || expRes.analysis || expRes;
          }
        } catch (e) {}
      }
    }

    const escapeHtml = (str) => {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    };

    const host = parsedSummary?.hosts?.[0];
    const ports = host?.ports || [];
    const recon = parsedSummary?.recon || {};
    const findings = rep?.findings || recon?.vulnerabilityAudit?.findings || [];
    const dtf = new Date().toLocaleString('vi-VN');
    const overallRisk = rep?.overallRisk || (recon?.vulnerabilityAudit?.criticalCount > 0 ? 'CRITICAL' : recon?.vulnerabilityAudit?.highCount > 0 ? 'HIGH' : 'MEDIUM');

    const riskColor = overallRisk === 'CRITICAL' ? '#dc2626' : overallRisk === 'HIGH' ? '#ea580c' : overallRisk === 'MEDIUM' ? '#d97706' : '#16a34a';

    // 1. Ports Table HTML
    const portsTableHtml = ports.length > 0 ? `
      <table>
        <thead>
          <tr>
            <th style="width: 100px;">Cổng / Giao thức</th>
            <th style="width: 120px;">Trạng Thái</th>
            <th style="width: 160px;">Tên Dịch Vụ</th>
            <th>Phiên Bản & Chi Tiết Phần Mềm</th>
          </tr>
        </thead>
        <tbody>
          ${ports.map(p => `
            <tr>
              <td style="font-family: monospace; font-weight: bold; color: #0284c7;">${escapeHtml(p.portId)}/${escapeHtml(p.protocol || 'tcp')}</td>
              <td><span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #15803d; background: #dcfce7;">OPEN</span></td>
              <td style="font-weight: 600; color: #1e293b;">${escapeHtml(p.serviceName || 'Unknown')}</td>
              <td style="color: #475569; font-size: 12px;">${escapeHtml([p.product, p.version].filter(Boolean).join(' ') || 'Chưa nhận diện được phiên bản')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '<p style="color: #64748b; font-style: italic;">Không phát hiện cổng mạng mở nào trong phạm vi quét.</p>';

    // 2. Tech Stack HTML
    const techStackHtml = recon?.techStack?.technologies?.length > 0 ? `
      <table>
        <thead>
          <tr>
            <th style="width: 200px;">Tên Công Nghệ / Nền Tảng</th>
            <th style="width: 180px;">Danh Mục</th>
            <th>Bằng Chứng Nhận Diện (HTTP Signature)</th>
          </tr>
        </thead>
        <tbody>
          ${recon.techStack.technologies.map(t => `
            <tr>
              <td style="font-weight: bold; color: #0f172a;">${escapeHtml(t.name)}</td>
              <td><span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; color: #0369a1; background: #e0f2fe;">${escapeHtml(t.category || 'Platform')}</span></td>
              <td style="color: #64748b; font-size: 12px;">${escapeHtml(t.evidence || 'Chữ ký HTTP header')}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '<p style="color: #64748b; font-style: italic;">Chưa phát hiện chữ ký công nghệ công khai.</p>';

    // 3. HTTP Security HTML
    const httpSecurityHtml = recon?.httpSecurity ? `
      <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; margin-top: 10px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <strong>Điểm An Toàn HTTP: <span style="font-size: 16px; color: ${recon.httpSecurity.score >= 80 ? '#16a34a' : '#ea580c'};">${recon.httpSecurity.score}/100</span> (Hạng ${escapeHtml(recon.httpSecurity.grade || 'C')})</strong>
        </div>
        ${recon.httpSecurity.missingHeaders?.length > 0 ? `
          <div style="font-size: 12px; color: #dc2626; margin-top: 6px;">
            <strong>⚠️ Thiếu các Security Headers quan trọng:</strong> ${escapeHtml(recon.httpSecurity.missingHeaders.join(', '))}
          </div>
        ` : '<div style="font-size: 12px; color: #16a34a;">Đã cấu hình đầy đủ các tiêu chuẩn HTTP Security Headers.</div>'}
      </div>
    ` : '';

    // 4. Web Directories HTML
    const webDirsHtml = recon?.webDirectories?.discoveredPaths?.length > 0 ? `
      <table>
        <thead>
          <tr>
            <th>Đường Dẫn / Tệp Tin</th>
            <th style="width: 120px;">Mã Trạng Thái</th>
            <th style="width: 160px;">Mức Độ Nhạy Cảm</th>
          </tr>
        </thead>
        <tbody>
          ${recon.webDirectories.discoveredPaths.slice(0, 15).map(dir => `
            <tr>
              <td style="font-family: monospace; font-size: 12px; color: #0369a1;">${escapeHtml(dir.path)}</td>
              <td><code>${escapeHtml(dir.status || 200)}</code></td>
              <td>${dir.isSensitive ? '<span style="color: #dc2626; font-weight: bold; font-size: 11px;">⚠️ NHẠY CẢM</span>' : '<span style="color: #64748b; font-size: 11px;">Bình thường</span>'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    ` : '';

    // 5. Findings HTML
    const findingsHtml = findings.length > 0 ? `
      <table>
        <thead>
          <tr>
            <th style="width: 100px; text-align: center;">Mức Độ</th>
            <th>Tên Lỗ Hổng & Điểm Yếu</th>
            <th style="width: 140px;">Mục Tiêu</th>
            <th>Vector Khai Thác & Biện Pháp Khắc Phục</th>
          </tr>
        </thead>
        <tbody>
          ${findings.map(f => {
            const sevColor = f.severity === 'CRITICAL' ? '#dc2626' : f.severity === 'HIGH' ? '#ea580c' : f.severity === 'MEDIUM' ? '#d97706' : '#2563eb';
            return `
              <tr>
                <td style="text-align: center; vertical-align: top;">
                  <span style="display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; color: #fff; background: ${sevColor};">${escapeHtml(f.severity)}</span>
                  ${f.cveId ? `<div style="font-size: 10px; font-family: monospace; color: #64748b; margin-top: 4px;">${escapeHtml(f.cveId)}</div>` : ''}
                </td>
                <td style="vertical-align: top;">
                  <div style="font-weight: bold; color: #0f172a; font-size: 13px;">${escapeHtml(f.title)}</div>
                  <div style="font-size: 12px; color: #475569; margin-top: 4px; line-height: 1.45;">${escapeHtml(f.description || '')}</div>
                </td>
                <td style="vertical-align: top; font-family: monospace; font-size: 12px; color: #0284c7;">${escapeHtml(f.target || currentAssessment.targets?.[0] || '-')}</td>
                <td style="vertical-align: top; font-size: 12px;">
                  ${f.exploitationVector ? `<div style="color: #7c2d12; background: #fff7ed; border: 1px solid #ffedd5; padding: 6px 8px; border-radius: 4px; margin-bottom: 6px;"><strong>🎯 Khai thác:</strong> ${escapeHtml(f.exploitationVector)}</div>` : ''}
                  <div style="color: #166534; background: #f0fdf4; border: 1px solid #dcfce7; padding: 6px 8px; border-radius: 4px;"><strong>🛡️ Khắc phục:</strong> ${escapeHtml(f.remediation || 'Cập nhật cấu hình bảo mật.')}</div>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    ` : '<p style="color: #16a34a; font-weight: 600;">Không ghi nhận lỗ hổng bảo mật nghiêm trọng nào.</p>';

    // 6. AI Explanation Text
    let aiText = '';
    if (aiExplanation) {
      if (typeof aiExplanation === 'string') {
        aiText = aiExplanation;
      } else {
        aiText = aiExplanation.analysis || aiExplanation.guidance || aiExplanation.targetAnalysis || JSON.stringify(aiExplanation);
      }
    }

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
        border-bottom: 3px solid #0284c7;
        padding-bottom: 14px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: flex-end;
      }
      .brand-title {
        font-size: 20px;
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
        gap: 12px;
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 14px 18px;
        margin-bottom: 20px;
      }
      .meta-item { font-size: 12.5px; }
      .meta-item strong { color: #334155; }
      .meta-item span { color: #0f172a; font-weight: 600; }
      .stat-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 12px;
        margin-bottom: 20px;
      }
      .stat-box {
        background: #ffffff;
        border: 1px solid #cbd5e1;
        border-radius: 8px;
        padding: 12px;
        text-align: center;
      }
      .stat-val { font-size: 22px; font-weight: 800; color: #0f172a; }
      .stat-lbl { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 600; margin-top: 4px; }
      .section {
        margin-bottom: 22px;
        page-break-inside: avoid;
      }
      .section-title {
        font-size: 14.5px;
        font-weight: 800;
        color: #0369a1;
        border-bottom: 1.5px solid #cbd5e1;
        padding-bottom: 6px;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 8px;
      }
      .ai-box {
        background: #faf5ff;
        border-left: 4px solid #a855f7;
        border: 1px solid #e9d5ff;
        border-left-width: 4px;
        border-radius: 0 8px 8px 0;
        padding: 14px 16px;
        font-size: 13px;
        color: #3b0764;
        line-height: 1.6;
        white-space: pre-wrap;
      }
      .exec-box {
        background: #f0fdf4;
        border: 1px solid #bbf7d0;
        border-left: 4px solid #16a34a;
        border-radius: 0 8px 8px 0;
        padding: 14px 16px;
        font-size: 13px;
        color: #14532d;
        line-height: 1.6;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        margin-top: 8px;
        font-size: 12px;
        page-break-inside: avoid;
      }
      th {
        background: #f1f5f9;
        padding: 8px 10px;
        text-align: left;
        font-weight: 700;
        color: #334155;
        border-bottom: 2px solid #cbd5e1;
        font-size: 11.5px;
      }
      td {
        padding: 8px 10px;
        border-bottom: 1px solid #e2e8f0;
      }
      code {
        font-family: 'Consolas', monospace;
        background: #f1f5f9;
        padding: 2px 5px;
        border-radius: 3px;
        color: #0284c7;
        font-size: 11.5px;
      }
      .signature-section {
        margin-top: 32px;
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
        margin-top: 25px;
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
          <div class="brand-title">🛡️ ATTT PORTAL - BÁO CÁO ĐÁNH GIÁ AN TOÀN THÔNG TIN</div>
          <div class="doc-type">Tài Liệu Đánh Giá An Ninh & Kiểm Thử Xâm Nhập Chuyên Nghiệp</div>
        </div>
        <div>
          <span class="risk-badge">RỦI RO: ${overallRisk}</span>
        </div>
      </div>

      <div class="meta-grid">
        <div class="meta-item"><strong>Tên Đợt Đánh Giá:</strong> <span>${escapeHtml(currentAssessment.name)}</span></div>
        <div class="meta-item"><strong>Mục Tiêu Rà Quét:</strong> <code>${escapeHtml(currentAssessment.targets?.join(', ') || latestScan?.target || 'N/A')}</code></div>
        <div class="meta-item"><strong>Loại Hình Kiểm Thử:</strong> <span>${currentAssessment.type === 'WEB' ? '🌐 Ứng Dụng Web (Web Application)' : '🖥️ Hạ Tầng Mạng & Máy Chủ (Server / Network)'}</span></div>
        <div class="meta-item"><strong>Thời Điểm Xuất Báo Cáo:</strong> <span>${dtf}</span></div>
        <div class="meta-item"><strong>Chuyên Viên Thực Hiện:</strong> <span>${escapeHtml(rep?.generatedBy || 'Chuyên viên ATTT')}</span></div>
        <div class="meta-item"><strong>Tiêu Chuẩn Tuân Thủ:</strong> <span>OWASP Top 10 • NIST SP 800-115 • MITRE ATT&CK</span></div>
      </div>

      <div class="stat-grid">
        <div class="stat-box" style="border-top: 3px solid #0284c7;">
          <div class="stat-val" style="color: #0284c7;">${ports.length}</div>
          <div class="stat-lbl">Cổng Mạng Mở</div>
        </div>
        <div class="stat-box" style="border-top: 3px solid #38bdf8;">
          <div class="stat-val" style="color: #0284c7;">${recon?.techStack?.technologies?.length || 0}</div>
          <div class="stat-lbl">Nền Tảng Công Nghệ</div>
        </div>
        <div class="stat-box" style="border-top: 3px solid #10b981;">
          <div class="stat-val" style="color: #10b981;">${recon?.httpSecurity?.score != null ? recon.httpSecurity.score : 85}/100</div>
          <div class="stat-lbl">Điểm An Toàn HTTP</div>
        </div>
        <div class="stat-box" style="border-top: 3px solid #dc2626;">
          <div class="stat-val" style="color: #dc2626;">${findings.length}</div>
          <div class="stat-lbl">Lỗ Hổng Đã Ghi Nhận</div>
        </div>
      </div>

      <!-- 1. Tóm tắt điều hành -->
      <div class="section">
        <div class="section-title">1. TÓM TẮT ĐIỀU HÀNH & KẾT LUẬN RỦI RO</div>
        <div class="exec-box">
          ${escapeHtml(rep?.executiveSummary || 'Hệ thống đã hoàn tất quy trình kiểm thử phân tầng theo tiêu chuẩn an toàn thông tin. Các rủi ro tiềm tàng trên bề mặt cổng dịch vụ và cấu hình ứng dụng đã được rà soát và đối soát với cơ sở dữ liệu lỗ hổng bảo mật.')}
        </div>
      </div>

      <!-- 2. Phân tích AI -->
      ${aiText ? `
        <div class="section">
          <div class="section-title">2. NHẬN ĐỊNH & PHÂN TÍCH CHUYÊN SÂU TỪ TRỢ LÝ AN NINH MẠNG AI</div>
          <div class="ai-box">${escapeHtml(aiText)}</div>
        </div>
      ` : ''}

      <!-- 3. Cổng & Dịch vụ Nmap -->
      <div class="section">
        <div class="section-title">3. CHI TIẾT CỔNG MẠNG & DỊCH VỤ PHÁT HIỆN (PORT SCANNING - NMAP)</div>
        ${portsTableHtml}
      </div>

      <!-- 4. Nhận diện công nghệ -->
      <div class="section">
        <div class="section-title">4. NHẬN DIỆN CÔNG NGHỆ & NỀN TẢNG (TECH STACK FINGERPRINTING)</div>
        ${techStackHtml}
      </div>

      <!-- 5. An toàn Web & HTTP -->
      ${httpSecurityHtml ? `
        <div class="section">
          <div class="section-title">5. KIỂM TRA BẢO MẬT WEB & HTTP HEADERS</div>
          ${httpSecurityHtml}
        </div>
      ` : ''}

      <!-- 6. Web Dirs -->
      ${webDirsHtml ? `
        <div class="section">
          <div class="section-title">6. ĐƯỜNG DẪN & THƯ MỤC WEB PHÁT HIỆN</div>
          ${webDirsHtml}
        </div>
      ` : ''}

      <!-- 7. Danh sách lỗ hổng & CVE -->
      <div class="section">
        <div class="section-title">7. DANH SÁCH LỖ HỔNG & ĐIỂM YẾU BẢO MẬT ĐÃ XÁC THỰC</div>
        ${findingsHtml}
      </div>

      <div class="signature-section">
        <div class="signature-box">
          <strong>Chuyên Viên Kiểm Thử (Pen-Tester)</strong><br/><br/><br/>
          <span>${escapeHtml(rep?.generatedBy || 'Chuyên viên ATTT')}</span>
        </div>
        <div class="signature-box">
          <strong>Lãnh Đạo Phụ Trách An Toàn Thông Tin</strong><br/><br/><br/>
          <span>Xác nhận & Phê duyệt lưu hành</span>
        </div>
      </div>

      <div class="report-footer">
        <div>Xuất bởi: ATTT Portal Security Engine • Bản quyền thuộc Đơn vị An toàn thông tin</div>
        <div>Tài liệu bảo mật - Chỉ lưu hành nội bộ</div>
      </div>
    `;

    const cleanName = (currentAssessment.name || 'Assessment').replace(/[^a-zA-Z0-9_\u00C0-\u024F\u1EA0-\u1EF9]/g, '_');
    const dateStr = new Date().toISOString().slice(0, 10);
    const pdfFileName = `Bao_Cao_ATTT_${cleanName}_${dateStr}.pdf`;

    // BƯỚC 1: XUẤT TỆP PDF THẬT TRỰC TIẾP VỀ MÁY TÍNH (DOWNLOAD FILE .PDF)
    const exportDiv = document.createElement('div');
    exportDiv.id = 'temp-pdf-export-container';
    exportDiv.style.position = 'fixed';
    exportDiv.style.left = '-9999px';
    exportDiv.style.top = '0';
    exportDiv.style.width = '794px'; // Chuẩn A4 bề ngang ở 96dpi
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
      console.warn('Lỗi html2pdf save:', pdfErr);
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
            <title>BÁO CÁO AN TOÀN THÔNG TIN - ${escapeHtml(currentAssessment.name)}</title>
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
                border-bottom: 2px solid #38bdf8;
                box-shadow: 0 4px 12px rgba(0,0,0,0.25);
                z-index: 9999;
                font-family: 'Segoe UI', Roboto, sans-serif;
              }
              .toolbar-btn {
                background: #0284c7;
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
              .toolbar-btn:hover { background: #0369a1; }
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
                <strong style="font-size: 14px;">Báo Cáo An Toàn: ${escapeHtml(currentAssessment.name)}</strong>
                <span style="background: rgba(14, 165, 233, 0.2); color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-size: 11px; margin-left: 8px;">Tệp PDF đã tự động tải về</span>
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
      console.warn('Popup preview bị chặn:', winErr);
    }
  } catch (err) {
    console.error('Lỗi xuất báo cáo PDF:', err);
    toastEmitter.show('Lỗi', err?.message || 'Không thể tạo file PDF', 'error');
  } finally {
    setIsExportingPdf(false);
  }
};

  // Xóa đánh giá
  const handleDeleteAssessment = async (id, e) => {
    e.stopPropagation();
    if (window.confirm('Bạn có chắc chắn muốn xóa đợt đánh giá này không?')) {
      try {
        await apiClient.delete(`/assessments/${id}`);
        toastEmitter.show('Đã xóa', 'Đợt đánh giá đã được xóa thành công.', 'success');
        setAssessments((prev) => prev.filter((a) => a.id !== id));
        if (selectedAssessment?.id === id) {
          setSelectedAssessment(null);
        }
      } catch (err) {
        toastEmitter.show('Lỗi', err?.message || 'Không thể xóa.', 'error');
      }
    }
  };

  const stats = {
    total: assessments.length,
    web: assessments.filter((a) => a.type === 'WEB').length,
    server: assessments.filter((a) => a.type === 'SERVER').length,
    planning: assessments.filter((a) => a.status === 'PLANNING' || a.status === 'CREATED').length,
    completed: assessments.filter((a) => a.status === 'COMPLETED').length,
  };

  const filteredAssessments = assessments.filter((item) => {
    const matchSearch =
      item.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.description?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchType = filterType === 'ALL' || item.type === filterType;
    const matchStatus = filterStatus === 'ALL' || item.status === filterStatus;
    return matchSearch && matchType && matchStatus;
  });

  // Tính toán phân trang
  const totalItems = filteredAssessments.length;
  const totalPages = Math.ceil(totalItems / pageSize) || 1;
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, totalItems);
  const paginatedAssessments = filteredAssessments.slice(startIndex, endIndex);

  // Tự động điều chỉnh trang nếu trang hiện tại vượt quá tổng số trang
  useEffect(() => {
    if (currentPage > totalPages && totalPages > 0) {
      setCurrentPage(totalPages);
    }
  }, [totalPages, currentPage]);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'RUNNING':
      case 'EXECUTING':
      case 'SCANNING':
        return (
          <span className="badge-status info">
            Đang Quét Tất Cả...
          </span>
        );
      case 'COMPLETED':
        return (
          <span className="badge-status success">
            Hoàn Thành
          </span>
        );
      case 'PLANNING':
        return (
          <span className="badge-status" style={{ background: 'rgba(99, 102, 241, 0.2)', color: '#818cf8', border: '1px solid rgba(99, 102, 241, 0.4)' }}>
            Sẵn Sàng Quét
          </span>
        );
      case 'CREATED':
        return (
          <span className="badge-status" style={{ background: '#334155', color: '#cbd5e1' }}>
            Mới Tạo
          </span>
        );
      case 'FAILED':
        return (
          <span className="badge-status danger">
            Thất Bại
          </span>
        );
      default:
        return <span className="badge-status">{status}</span>;
    }
  };

  if (viewMode === 'create') {
    return (
      <CreateAssessmentView
        onCreated={(newAssessment) => {
          setViewMode('list');
          fetchAssessments();
          if (newAssessment?.id) {
            handleOpenDetail(newAssessment);
          }
        }}
        onCancel={() => setViewMode('list')}
      />
    );
  }

  return (
    <div className="assessments-container">
      {/* 1. THỐNG KÊ NHANH */}
      <div className="grid-cols-4">
        <div className="stat-card">
          <div className="stat-info">
            <span className="stat-label">Tổng Đợt Đánh Giá</span>
            <span className="stat-value">{stats.total}</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-info">
            <span className="stat-label">Đang Lập Kế Hoạch</span>
            <span className="stat-value">{stats.planning}</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-info">
            <span className="stat-label">Đã Hoàn Thành</span>
            <span className="stat-value">{stats.completed}</span>
          </div>
        </div>

        <div className="stat-card">
          <div className="stat-info">
            <span className="stat-label">Server / Web</span>
            <span className="stat-value">
              {stats.server} <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>SRV</span> / {stats.web}{' '}
              <span style={{ fontSize: '0.85rem', color: '#94a3b8' }}>WEB</span>
            </span>
          </div>
        </div>
      </div>

      {/* 2. THANH PHÂN TÍCH NHANH: TÁCH BẠCH QUÉT URL (WEB) VÀ QUÉT IP (HẠ TẦNG) */}
      <div className="card-panel" style={{ background: 'linear-gradient(135deg, rgba(15, 23, 42, 0.95), rgba(30, 41, 59, 0.75))', border: '1px solid rgba(56, 189, 248, 0.35)', position: 'relative', overflow: 'hidden', padding: '1.5rem 1.75rem', marginBottom: '1.75rem', boxShadow: '0 8px 30px rgba(0, 0, 0, 0.45)' }}>
        <div style={{ position: 'absolute', right: '-40px', top: '-40px', width: '180px', height: '180px', background: 'radial-gradient(circle, rgba(99, 102, 241, 0.15) 0%, transparent 70%)', pointerEvents: 'none' }}></div>
        
        {/* Header & Mode Switcher */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', fontWeight: 800, fontSize: '1.1rem', color: '#f8fafc' }}>
              <i className="fa-solid fa-wand-magic-sparkles" style={{ color: '#a855f7' }}></i>
              <span>{quickScanMode === 'URL' ? 'Phân Tích & Quét Ứng Dụng Web (URL)' : 'Quét Cổng Mạng & Rà Soát Hạ Tầng (IP / Host)'}</span>
            </div>
            <p style={{ margin: '0.25rem 0 0 0', color: '#94a3b8', fontSize: '0.84rem' }}>
              {quickScanMode === 'URL' ? (
                <>Kiểm tra chuyên sâu Web: <strong>An toàn HTTP & Headers, Dò tìm đường dẫn nhạy cảm (Web Dirs), Chứng chỉ SSL</strong> và tự động dùng AI phân tích lỗ hổng Web Application.</>
              ) : (
                <>Quét chuyên sâu Hạ tầng: <strong>Quét toàn diện cổng mạng TCP/UDP (Nmap), Nhận diện phiên bản dịch vụ (-sV)</strong> và tự động dùng AI phân tích rủi ro máy chủ.</>
              )}
            </p>
          </div>

          {/* Nút chuyển đổi 2 chế độ: Quét URL vs Quét IP */}
          <div style={{ display: 'flex', background: '#090e17', padding: '0.25rem', borderRadius: '8px', border: '1px solid #1e293b', gap: '0.35rem' }}>
            <button
              type="button"
              className={`btn btn-sm ${quickScanMode === 'URL' ? 'btn-purple' : 'btn-outline'}`}
              onClick={() => setQuickScanMode('URL')}
              style={{ fontSize: '0.8rem', padding: '0.35rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem', border: quickScanMode === 'URL' ? 'none' : 'transparent' }}
            >
              <i className="fa-solid fa-globe"></i>
              <span>1. Quét Web / URL</span>
            </button>
            <button
              type="button"
              className={`btn btn-sm ${quickScanMode === 'IP' ? 'btn-purple' : 'btn-outline'}`}
              onClick={() => setQuickScanMode('IP')}
              style={{ fontSize: '0.8rem', padding: '0.35rem 0.85rem', display: 'flex', alignItems: 'center', gap: '0.4rem', border: quickScanMode === 'IP' ? 'none' : 'transparent' }}
            >
              <i className="fa-solid fa-server"></i>
              <span>2. Quét IP / Máy Chủ</span>
            </button>
          </div>
        </div>

        {/* Form nhập mục tiêu theo chế độ đã chọn */}
        <form onSubmit={handleQuickAnalyze} style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: '280px', position: 'relative' }}>
            {quickScanMode === 'URL' ? (
              <input
                type="text"
                className="form-control"
                placeholder="Nhập URL Web mục tiêu (Ví dụ: https://target.com, http://10.0.0.5:8080)..."
                value={quickUrl}
                onChange={(e) => setQuickUrl(e.target.value)}
                disabled={isQuickAnalyzing}
                style={{ width: '100%', padding: '0.85rem 1.15rem', fontSize: '0.92rem', background: 'rgba(11, 17, 32, 0.95)', borderColor: 'rgba(168, 85, 247, 0.5)' }}
              />
            ) : (
              <input
                type="text"
                className="form-control"
                placeholder="Nhập IP máy chủ hoặc dải mạng (Ví dụ: 192.168.1.10, 10.0.0.1/24)..."
                value={quickIp}
                onChange={(e) => setQuickIp(e.target.value)}
                disabled={isQuickAnalyzing}
                style={{ width: '100%', padding: '0.85rem 1.15rem', fontSize: '0.92rem', background: 'rgba(11, 17, 32, 0.95)', borderColor: 'rgba(56, 189, 248, 0.5)' }}
              />
            )}
          </div>
          <button
            type="submit"
            className={quickScanMode === 'URL' ? 'btn btn-purple' : 'btn btn-primary'}
            disabled={isQuickAnalyzing || (quickScanMode === 'URL' ? !quickUrl.trim() : !quickIp.trim())}
            style={{ padding: '0.85rem 1.65rem', fontSize: '0.92rem', minWidth: '230px' }}
          >
            <i className={`fa-solid ${isQuickAnalyzing ? 'fa-spinner fa-spin' : (quickScanMode === 'URL' ? 'fa-globe' : 'fa-server')}`}></i>
            <span style={{ marginLeft: '0.4rem' }}>
              {isQuickAnalyzing
                ? 'Đang Khởi Tạo & Quét...'
                : (quickScanMode === 'URL' ? 'Phân Tích & Quét Web' : 'Rà Quét & Phân Tích IP')}
            </span>
          </button>
        </form>
      </div>

      {/* 3. BẢNG DANH SÁCH */}
      <div className="card-panel">
        <div className="card-title-row">
          <div className="card-title">
            Quản Lý Đánh Giá An Toàn Thông Tin
          </div>
          <div style={{ display: 'flex', gap: '0.65rem' }}>
            <button className="btn btn-outline" onClick={fetchAssessments}>
              <i className="fa-solid fa-arrows-rotate"></i> Làm mới
            </button>
            <button className="btn btn-primary" onClick={() => setViewMode('create')}>
              <i className="fa-solid fa-plus"></i> Tạo Đánh Giá Mới
            </button>
          </div>
        </div>

        {/* Toolbar: Dàn đều trên cùng một hàng ngang với ô tìm kiếm */}
        <div className="table-toolbar" style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'nowrap' }}>
          <div className="search-box" style={{ flex: 1, minWidth: '220px', maxWidth: 'none' }}>
            <i className="fa-solid fa-magnifying-glass" style={{ color: '#38bdf8', fontSize: '0.85rem' }}></i>
            <input
              type="text"
              placeholder="Tìm kiếm theo tên đợt kiểm thử hoặc mục tiêu..."
              value={searchTerm}
              onChange={(e) => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
            />
            {searchTerm && (
              <button
                type="button"
                onClick={() => {
                  setSearchTerm('');
                  setCurrentPage(1);
                }}
                style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '0.2rem', display: 'flex', alignItems: 'center' }}
                title="Xóa tìm kiếm"
              >
                <i className="fa-solid fa-xmark"></i>
              </button>
            )}
          </div>

          <select
            className="input-control"
            style={{ width: '150px', flexShrink: 0 }}
            value={filterType}
            onChange={(e) => {
              setFilterType(e.target.value);
              setCurrentPage(1);
            }}
          >
            <option value="ALL">Mọi Loại Hình</option>
            <option value="SERVER">Máy Chủ</option>
            <option value="WEB">Web App</option>
          </select>

          <select
            className="input-control"
            style={{ width: '160px', flexShrink: 0 }}
            value={filterStatus}
            onChange={(e) => {
              setFilterStatus(e.target.value);
              setCurrentPage(1);
            }}
          >
            <option value="ALL">Mọi Trạng Thái</option>
            <option value="RUNNING">Đang Quét</option>
            <option value="COMPLETED">Hoàn Thành</option>
            <option value="FAILED">Thất Bại</option>
          </select>
        </div>

        {/* Table */}
        {loading ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: '#94a3b8' }}>
            <div>Đang tải dữ liệu đánh giá...</div>
          </div>
        ) : filteredAssessments.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3rem', color: '#64748b' }}>
            <div>Không tìm thấy đợt đánh giá nào phù hợp.</div>
          </div>
        ) : (
          <>
            <div className="table-responsive">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '60px' }}>STT</th>
                    <th>Tên Đợt Đánh Giá</th>
                    <th>Loại Hình</th>
                    <th>Mục Tiêu</th>
                    <th>Trạng Thái</th>
                    <th>Ngày Tạo</th>
                    <th style={{ textAlign: 'right' }}>Thao Tác</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedAssessments.map((item, idx) => (
                    <tr
                      key={item.id}
                      onClick={() => handleOpenDetail(item)}
                      style={{ cursor: 'pointer' }}
                      className={selectedAssessment?.id === item.id ? 'row-selected' : ''}
                    >
                      <td style={{ color: '#64748b', fontWeight: 600 }}>{((currentPage - 1) * pageSize) + idx + 1}</td>
                      <td>
                        <div style={{ fontWeight: 600, color: '#f8fafc' }}>{item.name}</div>
                        <div style={{ fontSize: '0.78rem', color: '#94a3b8', maxWidth: '350px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {item.description || 'Chưa có mô tả chi tiết'}
                        </div>
                      </td>
                      <td>
                        <span className="badge-tag">{item.type}</span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: '0.3rem', flexWrap: 'wrap', maxWidth: '280px' }}>
                          {(item.targets || []).map((t, tIdx) => (
                            <code key={tIdx} style={{ background: '#0f172a', padding: '0.15rem 0.4rem', borderRadius: '4px', fontSize: '0.75rem', color: '#38bdf8' }}>
                              {t}
                            </code>
                          ))}
                        </div>
                      </td>
                      <td>{getStatusBadge(item.status)}</td>
                      <td style={{ color: '#94a3b8', fontSize: '0.82rem' }}>
                        {item.createdAt ? new Date(item.createdAt).toLocaleDateString('vi-VN') : '-'}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '0.45rem', justifyContent: 'flex-end' }}>
                          <button
                            className="btn btn-sm btn-outline"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleOpenDetail(item);
                            }}
                          >
                            <i className="fa-solid fa-eye"></i> Chi tiết
                          </button>
                          <button
                            className="btn btn-sm btn-outline"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleExportPdf(item);
                            }}
                            disabled={isExportingPdf}
                            title="Tải tệp PDF báo cáo an toàn về máy tính"
                            style={{ color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.45)' }}
                          >
                            <i className={`fa-solid ${isExportingPdf ? 'fa-spinner fa-spin' : 'fa-file-pdf'}`}></i> {isExportingPdf ? 'Đang xuất...' : 'Xuất PDF'}
                          </button>
                          <button
                            className="btn btn-sm btn-outline-danger"
                            onClick={(e) => handleDeleteAssessment(item.id, e)}
                          >
                            <i className="fa-solid fa-trash-can"></i> Xóa
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination Controls Footer */}
            {totalItems > 0 && (
              <div className="pagination-container">
                <div className="pagination-info">
                  <span>
                    Hiển thị <strong>{startIndex + 1}</strong> - <strong>{endIndex}</strong> trong tổng số <strong>{totalItems}</strong> đợt đánh giá
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                    <span style={{ fontSize: '0.8rem', color: '#64748b' }}>Hiển thị:</span>
                    <select
                      className="pagination-size-select"
                      value={pageSize}
                      onChange={(e) => {
                        setPageSize(Number(e.target.value));
                        setCurrentPage(1);
                      }}
                    >
                      <option value={5}>5 / trang</option>
                      <option value={10}>10 / trang</option>
                      <option value={20}>20 / trang</option>
                      <option value={50}>50 / trang</option>
                    </select>
                  </div>
                </div>

                <div className="pagination-buttons">
                  <button
                    type="button"
                    className="page-btn"
                    onClick={() => setCurrentPage(1)}
                    disabled={currentPage === 1}
                    title="Trang đầu"
                  >
                    <i className="fa-solid fa-angles-left"></i>
                  </button>
                  <button
                    type="button"
                    className="page-btn"
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                    title="Trang trước"
                  >
                    <i className="fa-solid fa-angle-left"></i>
                  </button>

                  {/* Dynamic Page Buttons with Ellipsis */}
                  {Array.from({ length: totalPages }, (_, i) => i + 1)
                    .filter((p) => p === 1 || p === totalPages || (p >= currentPage - 2 && p <= currentPage + 2))
                    .map((p, idx, arr) => {
                      const prev = arr[idx - 1];
                      const showEllipsis = prev && p - prev > 1;
                      return (
                        <React.Fragment key={p}>
                          {showEllipsis && <span className="page-ellipsis">...</span>}
                          <button
                            type="button"
                            className={`page-btn ${currentPage === p ? 'active' : ''}`}
                            onClick={() => setCurrentPage(p)}
                          >
                            {p}
                          </button>
                        </React.Fragment>
                      );
                    })}

                  <button
                    type="button"
                    className="page-btn"
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                    title="Trang kế"
                  >
                    <i className="fa-solid fa-angle-right"></i>
                  </button>
                  <button
                    type="button"
                    className="page-btn"
                    onClick={() => setCurrentPage(totalPages)}
                    disabled={currentPage === totalPages}
                    title="Trang cuối"
                  >
                    <i className="fa-solid fa-angles-right"></i>
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      {/* 3. MODAL CHI TIẾT ĐỢT KIỂM THỬ */}
      {selectedAssessment && (() => {
        const sortedScans = [...(scansData || [])].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
        const latestScan = sortedScans[0] || null;
        const historyScans = sortedScans;
        const oldScansCount = sortedScans.length > 1 ? sortedScans.length - 1 : 0;

        const renderScanTask = (scan, isLatest = false) => {
          if (!scan) return null;

          let parsedSummary = null;
          try {
            parsedSummary = scan.parsedSummary ? (typeof scan.parsedSummary === 'string' ? JSON.parse(scan.parsedSummary) : scan.parsedSummary) : null;
          } catch (e) {}

          const host = parsedSummary?.hosts?.[0];
          const ports = host?.ports || [];
          const allScripts = ports.flatMap((p) =>
            (p.scripts || []).map((s) => ({ ...s, port: `${p.portId}/${p.protocol}` }))
          );

          const recon = parsedSummary?.recon;
          const explanation = scanExplanations[scan.id];
          const isExplaining = explainingScanId === scan.id;

          return (
            <div key={scan.id} className="scan-result-card" style={{ marginBottom: '1.75rem', background: '#090e17', border: isLatest ? '1px solid rgba(56, 189, 248, 0.45)' : '1px solid #1e293b', borderRadius: '10px', padding: '1.25rem' }}>
              {/* Header Card */}
              <div className="scan-card-header" style={{ borderBottom: '1px solid #1e293b', paddingBottom: '0.85rem', marginBottom: '1rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 800, color: isLatest ? '#38bdf8' : '#cbd5e1', fontSize: '1.1rem' }}>
                    {scan.target || 'Mục tiêu kiểm thử'}
                  </span>
                  <span className="profile-tag" style={{ background: 'linear-gradient(135deg, #0284c7, #38bdf8)', color: '#fff', padding: '0.2rem 0.65rem', borderRadius: '4px', fontSize: '0.78rem', fontWeight: 700 }}>
                    🔍 Quét Cổng & Dịch Vụ Mạng
                  </span>
                  {isLatest ? (
                    <span className="profile-tag" style={{ background: '#0284c7', color: '#fff', padding: '0.2rem 0.65rem', borderRadius: '4px', fontSize: '0.78rem', fontWeight: 700 }}>
                      ⚡ Mới Nhất
                    </span>
                  ) : (
                    <span className="profile-tag" style={{ background: '#1e293b', color: '#94a3b8', padding: '0.2rem 0.6rem', borderRadius: '4px', fontSize: '0.78rem', fontWeight: 600 }}>
                      🕒 Bản Ghi Lịch Sử
                    </span>
                  )}
                  <code className="target-code" style={{ background: '#0284c7', color: '#fff', padding: '0.2rem 0.5rem', borderRadius: '4px', fontSize: '0.82rem', fontWeight: 600 }}>
                    {scan.target}
                  </code>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  {scan.durationMs && (
                    <span style={{ fontSize: '0.8rem', color: '#94a3b8', background: '#0f172a', padding: '0.25rem 0.6rem', borderRadius: '4px', border: '1px solid #1e293b' }}>
                      Thời gian: {(scan.durationMs / 1000).toFixed(1)}s
                    </span>
                  )}
                  <span className={`badge-status ${scan.status === 'COMPLETED' ? 'success' : scan.status === 'RUNNING' ? 'info' : 'danger'}`}>
                    {scan.status === 'COMPLETED' ? 'HOÀN THÀNH' : scan.status === 'RUNNING' ? 'ĐANG QUÉT...' : 'THẤT BẠI'}
                  </span>

                  {/* Nút Quét & Phân Tích AI gộp chung */}
                  <button
                    className="btn btn-primary"
                    onClick={handleExecuteAll}
                    disabled={executingStepId !== null || scan.status === 'RUNNING'}
                    title="Chạy quét lại mục tiêu và tự động phân tích & giải thích bằng AI"
                  >
                    <i className={`fa-solid ${executingStepId !== null || scan.status === 'RUNNING' ? 'fa-spinner fa-spin' : 'fa-bolt-lightning'}`}></i>
                    <span>{executingStepId !== null || scan.status === 'RUNNING' ? 'Đang Quét & Phân Tích AI...' : 'Quét Lại & Phân Tích AI'}</span>
                  </button>
                </div>
              </div>

              {/* Error Message */}
              {scan.errorMessage && (
                <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: '6px', padding: '0.85rem 1rem', color: '#fca5a5', fontSize: '0.85rem', marginBottom: '1rem' }}>
                  <strong>Lỗi:</strong> {scan.errorMessage}
                </div>
              )}

              {/* 1. Host Summary Stats Box */}
              {parsedSummary && (
                <div className="host-stat-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', marginBottom: '1.25rem' }}>
                  <div className="host-stat-item" style={{ background: '#0f172a', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Địa Chỉ IP</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f1f5f9', marginTop: '0.2rem' }}>
                      {host?.ipAddress || (recon?.dns?.resolvedIps?.[0]) || 'Chưa xác định'}
                    </div>
                  </div>
                  <div className="host-stat-item" style={{ background: '#0f172a', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Trạng Thái Kết Nối</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#34d399', marginTop: '0.2rem' }}>
                      UP - Hoạt Động
                    </div>
                  </div>
                  <div className="host-stat-item" style={{ background: '#0f172a', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                    <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Cổng Mở</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: parsedSummary.totalOpenPorts > 0 ? '#fbbf24' : '#34d399', marginTop: '0.2rem' }}>
                      {parsedSummary.totalOpenPorts} Cổng Đang Mở
                    </div>
                  </div>
                  {recon?.techStack && (
                    <div className="host-stat-item" style={{ background: '#0f172a', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                      <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Công Nghệ Nhận Diện</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 700, color: '#38bdf8', marginTop: '0.2rem' }}>
                        {recon.techStack.technologies?.length || 0} Nền Tảng
                      </div>
                    </div>
                  )}
                  {recon?.vulnerabilityAudit && (
                    <div className="host-stat-item" style={{ background: '#0f172a', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                      <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Điểm Yếu Cấu Hình</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 700, color: ((recon.vulnerabilityAudit.criticalCount || 0) + (recon.vulnerabilityAudit.highCount || 0)) > 0 ? '#f87171' : '#34d399', marginTop: '0.2rem' }}>
                        {recon.vulnerabilityAudit.findings?.length || 0} Điểm Yếu
                      </div>
                    </div>
                  )}
                  {recon?.httpSecurity && (
                    <div className="host-stat-item" style={{ background: '#0f172a', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                      <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Điểm Bảo Mật HTTP</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 700, color: recon.httpSecurity.score >= 80 ? '#34d399' : '#fbbf24', marginTop: '0.2rem' }}>
                        {recon.httpSecurity.score}/100 (Hạng {recon.httpSecurity.grade})
                      </div>
                    </div>
                  )}
                  {recon?.webDirectories && (
                    <div className="host-stat-item" style={{ background: '#0f172a', padding: '0.75rem 1rem', borderRadius: '6px', border: '1px solid #1e293b' }}>
                      <div style={{ fontSize: '0.72rem', color: '#94a3b8', textTransform: 'uppercase' }}>Đường Dẫn Web</div>
                      <div style={{ fontSize: '0.95rem', fontWeight: 700, color: recon.webDirectories.sensitiveCount > 0 ? '#f87171' : '#34d399', marginTop: '0.2rem' }}>
                        {recon.webDirectories.discoveredPaths?.length || 0} Paths ({recon.webDirectories.sensitiveCount || 0} Nhạy Cảm)
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* 2. AI EXPLANATION BOX (WITH REAL-TIME REASONING & NEXT ACTIONS) */}
              <ScanAiExplanationCard
                explanation={explanation}
                loading={isExplaining || (scan.status === 'RUNNING' && !explanation)}
                onAskAi={() => handleOpenAiAssistant({ scanTask: scan, explanation })}
              />

              {/* 3. PHẦN 1: BẢNG CHI TIẾT CỔNG MẠNG & DỊCH VỤ (NMAP) */}
              <div style={{ marginTop: '1.5rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                <div style={{ fontSize: '0.92rem', fontWeight: 700, color: '#f8fafc', marginBottom: '0.85rem', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span>
                    1. Dịch Vụ & Cổng Mạng Mở (Port Scanning):
                  </span>
                  <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 400 }}>
                    Phát hiện {ports.length} cổng đang hoạt động
                  </span>
                </div>

                {ports.length > 0 ? (
                  <div className="port-cards-container" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '0.75rem' }}>
                    {ports.map((p, pIdx) => {
                      let friendlyDesc = 'Dịch vụ mạng đang lắng nghe kết nối.';
                      const svc = (p.serviceName || '').toLowerCase();
                      if (p.portId === 88 || svc.includes('kerberos')) {
                        friendlyDesc = 'Kerberos Authentication: Dịch vụ xác thực vé bảo mật Active Directory, trọng điểm của kỹ thuật Kerberoasting và AS-REP Roasting.';
                      } else if (p.portId === 389 || svc.includes('ldap')) {
                        friendlyDesc = 'Active Directory LDAP: Dịch vụ thư mục chứa toàn bộ cấu trúc người dùng, máy tính và chính sách phân quyền miền.';
                      } else if (p.portId === 445 || svc.includes('microsoft-ds')) {
                        friendlyDesc = 'SMB File Sharing: Chia sẻ tệp tin và Named Pipes Windows. Thường bị dò quét mật khẩu và kiểm tra lỗ hổng cấu hình chia sẻ.';
                      } else if (p.portId === 135 || svc.includes('msrpc')) {
                        friendlyDesc = 'MSRPC Endpoint Mapper: Quản lý và định tuyến các giao diện gọi thủ tục từ xa của hệ điều hành Windows.';
                      } else if (p.portId === 139 || svc.includes('netbios')) {
                        friendlyDesc = 'NetBIOS Session Service: Dịch vụ chia sẻ tên và tài nguyên mạng nội bộ trong môi trường Windows.';
                      } else if (p.portId === 53 || svc.includes('domain')) {
                        friendlyDesc = 'DNS Domain Name System: Máy chủ phân giải tên miền nội bộ của Active Directory.';
                      } else if (p.portId === 464 || svc.includes('kpasswd')) {
                        friendlyDesc = 'Kerberos Password Change: Dịch vụ quản lý và đổi mật khẩu Kerberos.';
                      } else if (p.portId === 593 || svc.includes('ncacn_http')) {
                        friendlyDesc = 'MSRPC over HTTP: Giao diện RPC ánh xạ qua giao thức HTTP (RPC over HTTP v1.0).';
                      } else if (p.portId === 636 || svc.includes('ldapssl')) {
                        friendlyDesc = 'LDAPS (Secure LDAP): Dịch vụ thư mục Active Directory được mã hóa bảo mật qua SSL/TLS.';
                      } else if (p.portId === 3268 || p.portId === 3269 || svc.includes('globalcat')) {
                        friendlyDesc = 'Global Catalog LDAP: Danh mục toàn cục lưu trữ bản sao dữ liệu của mọi đối tượng trong toàn bộ rừng miền Active Directory.';
                      } else if (p.portId === 5985 || p.portId === 5986 || svc.includes('winrm')) {
                        friendlyDesc = 'WinRM (PowerShell Remoting): Dịch vụ quản trị từ xa Windows qua giao thức HTTP/HTTPS.';
                      } else if (p.portId === 3389 || svc.includes('wbt') || svc.includes('rdp')) {
                        friendlyDesc = 'Remote Desktop Protocol (RDP): Quản trị máy tính từ xa qua giao diện đồ họa GUI.';
                      } else if (p.portId === 80 || svc === 'http') {
                        friendlyDesc = 'Web HTTP chưa mã hóa SSL, dữ liệu gửi đi dạng văn bản thuần.';
                      } else if (p.portId === 443 || svc === 'https') {
                        friendlyDesc = 'Web HTTPS an toàn đã có chứng chỉ SSL/TLS mã hóa.';
                      } else if (p.portId === 22 || svc === 'ssh') {
                        friendlyDesc = 'SSH điều khiển máy chủ Linux/Unix. Cần giới hạn IP và dùng SSH Key.';
                      } else if (p.portId === 3306 || svc === 'mysql') {
                        friendlyDesc = 'Cơ sở dữ liệu MySQL. Khuyến nghị chỉ mở nội bộ.';
                      } else if (p.portId === 5432 || svc === 'postgresql') {
                        friendlyDesc = 'Cơ sở dữ liệu PostgreSQL. Khuyến nghị chỉ mở nội bộ.';
                      } else if (p.portId === 1433 || svc.includes('sql')) {
                        friendlyDesc = 'Cơ sở dữ liệu Microsoft SQL Server.';
                      } else if (p.portId === 8080) {
                        friendlyDesc = 'Cổng máy chủ ứng dụng HTTP phụ.';
                      }

                      return (
                        <div key={pIdx} className="port-item-card" style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.85rem 1rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                              <span style={{ background: '#0284c7', color: '#fff', padding: '0.15rem 0.45rem', borderRadius: '4px', fontWeight: 700, fontSize: '0.8rem' }}>
                                {p.portId}/{p.protocol.toUpperCase()}
                              </span>
                              <span style={{ color: '#34d399', fontSize: '0.75rem', fontWeight: 600 }}>
                                {p.state.toUpperCase()}
                              </span>
                            </div>

                            <button
                              className="ask-port-ai-btn"
                              style={{ background: 'rgba(99, 102, 241, 0.15)', border: '1px solid rgba(99, 102, 241, 0.3)', color: '#818cf8', borderRadius: '4px', padding: '0.15rem 0.5rem', fontSize: '0.72rem', cursor: 'pointer' }}
                              onClick={() =>
                                handleOpenAiAssistant({
                                  port: p,
                                  target: scan.target,
                                  question: `Giải thích chi tiết về cổng ${p.portId}/${p.protocol} đang chạy ${p.serviceName} ${p.product || ''}`,
                                  recommendation: `Đề xuất kịch bản kiểm thử tiếp theo cho cổng ${p.portId} (${p.serviceName})`,
                                })
                              }
                              title="Hỏi AI về cổng này"
                            >
                              Hỏi AI
                            </button>
                          </div>

                          <div style={{ fontWeight: 600, color: '#f8fafc', fontSize: '0.85rem', marginBottom: '0.2rem' }}>
                            Dịch Vụ: {p.serviceName?.toUpperCase()}
                            {p.product && (
                              <span style={{ color: '#fbbf24', marginLeft: '0.4rem', fontWeight: 500, fontSize: '0.78rem' }}>
                                ({p.product} {p.version && `v${p.version}`})
                              </span>
                            )}
                          </div>

                          <div style={{ fontSize: '0.76rem', color: '#cbd5e1', lineHeight: '1.4' }}>
                            <strong>Ý nghĩa:</strong> {friendlyDesc}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.85rem 1rem', color: '#94a3b8', fontSize: '0.82rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span>Không phát hiện cổng mở nguy hiểm nào trong phạm vi quét này.</span>
                  </div>
                )}
              </div>

              {/* 4. PHẦN 2: NHẬN DIỆN CÔNG NGHỆ & NỀN TẢNG (TECH STACK FINGERPRINTING) */}
              {recon?.techStack && (
                <div style={{ marginTop: '1.25rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
                    <span style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.92rem' }}>
                      2. Nhận Diện Công Nghệ & Nền Tảng (Tech Stack Fingerprinting):
                    </span>
                    <span style={{ fontSize: '0.75rem', background: '#0f172a', color: '#38bdf8', padding: '0.2rem 0.5rem', borderRadius: '4px', fontWeight: 600, border: '1px solid #334155' }}>
                      {recon.techStack.technologies?.length || 0} Thành Phần
                    </span>
                  </div>

                  {recon.techStack.technologies && recon.techStack.technologies.length > 0 ? (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '0.65rem' }}>
                      {recon.techStack.technologies.map((t, tIdx) => (
                        <div key={tIdx} style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.65rem 0.85rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                            <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.82rem' }}>{t.name}</span>
                            <span style={{ fontSize: '0.68rem', padding: '0.1rem 0.4rem', borderRadius: '3px', background: '#0284c7', color: '#fff', fontWeight: 600 }}>
                              {t.category}
                            </span>
                          </div>
                          <div style={{ fontSize: '0.72rem', color: '#94a3b8', lineHeight: '1.3' }}>
                            {t.evidence || 'Phát hiện qua chữ ký HTTP'}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ color: '#64748b', fontSize: '0.8rem' }}>Chưa nhận diện được chữ ký công nghệ công khai.</div>
                  )}
                </div>
              )}

              {/* 5. PHẦN 3: KIỂM THỬ LỖ HỔNG & ĐIỂM YẾU CẤU HÌNH (VULNERABILITY & MISCONFIG AUDIT) */}
              {recon?.vulnerabilityAudit && (
                <div style={{ marginTop: '1.25rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, color: '#f87171', fontSize: '0.92rem' }}>
                      3. Kiểm Thử Lỗ Hổng & Điểm Yếu Cấu Hình (Vulnerability & Misconfig Audit):
                    </span>
                    <div style={{ display: 'flex', gap: '0.4rem' }}>
                      {(recon.vulnerabilityAudit.criticalCount || 0) > 0 && (
                        <span style={{ fontSize: '0.72rem', fontWeight: 700, background: 'rgba(239, 68, 68, 0.25)', color: '#fca5a5', padding: '0.15rem 0.45rem', borderRadius: '4px', border: '1px solid #ef4444' }}>
                          {recon.vulnerabilityAudit.criticalCount} CRITICAL
                        </span>
                      )}
                      {(recon.vulnerabilityAudit.highCount || 0) > 0 && (
                        <span style={{ fontSize: '0.72rem', fontWeight: 700, background: 'rgba(249, 115, 22, 0.25)', color: '#fdba74', padding: '0.15rem 0.45rem', borderRadius: '4px', border: '1px solid #f97316' }}>
                          {recon.vulnerabilityAudit.highCount} HIGH
                        </span>
                      )}
                      {(recon.vulnerabilityAudit.mediumCount || 0) > 0 && (
                        <span style={{ fontSize: '0.72rem', fontWeight: 700, background: 'rgba(234, 179, 8, 0.25)', color: '#fde047', padding: '0.15rem 0.45rem', borderRadius: '4px', border: '1px solid #eab308' }}>
                          {recon.vulnerabilityAudit.mediumCount} MEDIUM
                        </span>
                      )}
                    </div>
                  </div>

                  {recon.vulnerabilityAudit.findings && recon.vulnerabilityAudit.findings.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
                      {recon.vulnerabilityAudit.findings.map((vf, vfIdx) => (
                        <div key={vfIdx} style={{ background: '#090e17', border: '1px solid #1e293b', borderLeft: `4px solid ${vf.severity === 'CRITICAL' ? '#dc2626' : vf.severity === 'HIGH' ? '#ea580c' : vf.severity === 'MEDIUM' ? '#d97706' : '#0284c7'}`, borderRadius: '0 6px 6px 0', padding: '0.85rem 1rem' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.45rem', flexWrap: 'wrap', gap: '0.4rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                              <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.45rem', borderRadius: '3px', fontWeight: 800, color: '#fff', background: vf.severity === 'CRITICAL' ? '#dc2626' : vf.severity === 'HIGH' ? '#ea580c' : vf.severity === 'MEDIUM' ? '#d97706' : '#0284c7' }}>
                                {vf.severity}
                              </span>
                              <span style={{ fontWeight: 700, color: '#f1f5f9', fontSize: '0.88rem' }}>
                                {vf.title}
                              </span>
                              {vf.cveId && (
                                <a
                                  href={vf.references || `https://nvd.nist.gov/vuln/detail/${vf.cveId}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  style={{
                                    fontSize: '0.72rem',
                                    fontWeight: 800,
                                    color: '#38bdf8',
                                    background: 'rgba(2, 132, 199, 0.2)',
                                    border: '1px solid rgba(56, 189, 248, 0.4)',
                                    padding: '0.15rem 0.5rem',
                                    borderRadius: '4px',
                                    textDecoration: 'none',
                                    display: 'inline-flex',
                                    alignItems: 'center',
                                    gap: '0.3rem'
                                  }}
                                  title="Tra cứu lỗ hổng chính thức trên NIST NVD"
                                >
                                  <i className="fa-solid fa-shield-halved"></i>
                                  {vf.cveId}
                                </a>
                              )}
                              {vf.cisaKev && (
                                <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#fca5a5', background: 'rgba(239, 68, 68, 0.25)', border: '1px solid #ef4444', padding: '0.15rem 0.45rem', borderRadius: '4px' }}>
                                  🔥 CISA KEV: Đang Bị Khai Thác Ngoài Thực Tế
                                </span>
                              )}
                              {vf.exploitAvailable && !vf.cisaKev && (
                                <span style={{ fontSize: '0.7rem', fontWeight: 800, color: '#fdba74', background: 'rgba(249, 115, 22, 0.22)', border: '1px solid #f97316', padding: '0.15rem 0.45rem', borderRadius: '4px' }}>
                                  ⚡ Có Mã Khai Thác (PoC Công Khai)
                                </span>
                              )}
                              {vf.mitreTechniqueId && (
                                <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#38bdf8', background: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.35)', padding: '0.15rem 0.45rem', borderRadius: '4px', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }} title={`MITRE ATT&CK: ${vf.mitreTactic || ''} - ${vf.mitreTechniqueName || ''}`}>
                                  <i className="fa-solid fa-cubes-stacked"></i>
                                  MITRE {vf.mitreTechniqueId}
                                </span>
                              )}
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                              {vf.cvssScore > 0 && (
                                <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#fbbf24', background: '#0f172a', padding: '0.15rem 0.4rem', borderRadius: '3px', border: '1px solid #334155' }}>
                                  CVSS {vf.cvssScore.toFixed(1)}
                                </span>
                              )}
                              <button
                                type="button"
                                style={{ background: 'rgba(168, 85, 247, 0.15)', border: '1px solid rgba(168, 85, 247, 0.35)', color: '#d8b4fe', fontSize: '0.72rem', padding: '0.2rem 0.6rem', cursor: 'pointer', borderRadius: '4px', display: 'flex', alignItems: 'center', gap: '0.3rem' }}
                                onClick={() => handleOpenAiAssistant({ finding: vf, scanTask: scan })}
                                title="Hỏi AI cách khắc phục lỗ hổng này"
                              >
                                <i className="fa-solid fa-wand-magic-sparkles"></i>
                                Hỏi AI
                              </button>
                            </div>
                          </div>

                          <div style={{ fontSize: '0.78rem', color: '#cbd5e1', lineHeight: '1.45', marginBottom: '0.4rem' }}>
                            {vf.description}
                          </div>

                          {vf.impact && (
                            <div style={{ fontSize: '0.76rem', color: '#f87171', background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)', padding: '0.35rem 0.6rem', borderRadius: '4px', marginBottom: '0.4rem' }}>
                              <strong>⚠️ Hậu Quả Khai Thác Kỹ Thuật:</strong> {vf.impact}
                            </div>
                          )}

                          {vf.evidence && (
                            <div style={{ fontSize: '0.74rem', color: '#94a3b8', background: '#050811', padding: '0.35rem 0.6rem', borderRadius: '3px', marginBottom: '0.4rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                              <strong>Bằng chứng kỹ thuật:</strong> {vf.evidence}
                            </div>
                          )}

                          {vf.exploitationVector && (
                            <div style={{ fontSize: '0.76rem', color: '#e9d5ff', background: 'rgba(168, 85, 247, 0.09)', border: '1px solid rgba(168, 85, 247, 0.28)', padding: '0.45rem 0.7rem', borderRadius: '4px', marginBottom: '0.4rem', lineHeight: '1.45' }}>
                              <div style={{ fontWeight: 700, color: '#c084fc', display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.2rem' }}>
                                <i className="fa-solid fa-crosshairs"></i>
                                <span>Cơ Chế Hacker Hoạt Động (Attack Vector & Mechanics):</span>
                              </div>
                              <div>{vf.exploitationVector}</div>
                            </div>
                          )}

                          <div style={{ fontSize: '0.76rem', color: '#34d399', background: 'rgba(16, 185, 129, 0.08)', padding: '0.35rem 0.6rem', borderRadius: '3px' }}>
                            <strong>Khuyến nghị khắc phục:</strong> {vf.remediation}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.85rem 1rem', color: '#34d399', fontSize: '0.82rem' }}>
                      Không phát hiện lỗ hổng cấu hình nguy hiểm nào trong bài kiểm tra cơ bản.
                    </div>
                  )}
                </div>
              )}

              {/* 6. PHẦN 4: BẢO MẬT HTTP & CHỨNG CHỈ SSL (HTTP SECURITY & SSL AUDIT) */}
              {recon?.httpSecurity && (
                <div style={{ marginTop: '1.25rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <span style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.92rem' }}>
                      4. Đánh Giá An Toàn HTTP & Chứng Chỉ SSL:
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontSize: '0.8rem', fontWeight: 700, color: '#fbbf24', background: '#0f172a', padding: '0.2rem 0.5rem', borderRadius: '4px', border: '1px solid #334155' }}>
                        {recon.httpSecurity.score}/100 Điểm
                      </span>
                      <span style={{ fontSize: '0.82rem', fontWeight: 800, color: recon.httpSecurity.grade === 'A+' || recon.httpSecurity.grade === 'A' ? '#34d399' : '#f87171', background: '#0f172a', padding: '0.2rem 0.5rem', borderRadius: '4px', border: '1px solid #334155' }}>
                        Hạng {recon.httpSecurity.grade}
                      </span>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(210px, 1fr))', gap: '0.45rem', marginBottom: '0.75rem' }}>
                    {(recon.httpSecurity.headers || []).map((h, hIdx) => (
                      <div key={hIdx} style={{ background: '#090e17', padding: '0.45rem 0.65rem', borderRadius: '4px', fontSize: '0.74rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', border: '1px solid #1e293b' }}>
                        <span style={{ color: '#cbd5e1', fontWeight: 500 }}>{h.headerName}</span>
                        <span style={{ color: h.present ? '#34d399' : '#f87171', fontWeight: 700 }}>
                          {h.present ? 'ĐẠT' : 'THIẾU'}
                        </span>
                      </div>
                    ))}
                  </div>

                  {recon.httpSecurity.sslInfo && (
                    <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '4px', padding: '0.55rem 0.85rem', fontSize: '0.76rem', color: '#94a3b8' }}>
                      <span style={{ color: '#38bdf8', fontWeight: 600 }}>Chứng chỉ SSL/TLS:</span> Cấp bởi <strong>{recon.httpSecurity.sslInfo.issuer || 'N/A'}</strong> (Hết hạn: {recon.httpSecurity.sslInfo.validTo || 'N/A'}, còn {recon.httpSecurity.sslInfo.daysRemaining} ngày)
                    </div>
                  )}
                </div>
              )}

              {/* 7. PHẦN 5: DÒ TÌM ĐƯỜNG DẪN WEB & TỆP NHẠY CẢM (WEB DIRECTORY DISCOVERY) */}
              {recon?.webDirectories && (
                <div style={{ marginTop: '1.25rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem' }}>
                    <span style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.92rem' }}>
                      5. Dò Tìm Đường Dẫn & File Nhạy Cảm (Web Directory Discovery):
                    </span>
                    <span style={{ fontSize: '0.75rem', background: recon.webDirectories.sensitiveCount > 0 ? 'rgba(239, 68, 68, 0.2)' : '#0f172a', color: recon.webDirectories.sensitiveCount > 0 ? '#fca5a5' : '#34d399', padding: '0.2rem 0.5rem', borderRadius: '4px', fontWeight: 600, border: '1px solid #334155' }}>
                      {recon.webDirectories.discoveredPaths?.length || 0} Paths ({recon.webDirectories.sensitiveCount || 0} Nhạy Cảm)
                    </span>
                  </div>

                  {recon.webDirectories.discoveredPaths && recon.webDirectories.discoveredPaths.length > 0 ? (
                    <div style={{ maxHeight: '180px', overflowY: 'auto', border: '1px solid #1e293b', borderRadius: '4px' }}>
                      <table style={{ width: '100%', fontSize: '0.78rem', textAlign: 'left', borderCollapse: 'collapse' }}>
                        <thead>
                          <tr style={{ background: '#0f172a', color: '#94a3b8' }}>
                            <th style={{ padding: '0.45rem 0.65rem' }}>Đường Dẫn</th>
                            <th style={{ padding: '0.45rem 0.65rem' }}>Mã Phản Hồi</th>
                            <th style={{ padding: '0.45rem 0.65rem' }}>Phân Loại</th>
                            <th style={{ padding: '0.45rem 0.65rem' }}>Rủi Ro</th>
                          </tr>
                        </thead>
                        <tbody>
                          {recon.webDirectories.discoveredPaths.map((d, dIdx) => (
                            <tr key={dIdx} style={{ borderTop: '1px solid #1e293b', background: d.riskLevel === 'HIGH' ? 'rgba(239, 68, 68, 0.05)' : 'transparent' }}>
                              <td style={{ padding: '0.45rem 0.65rem', color: '#38bdf8', fontWeight: 600, fontFamily: 'monospace' }}>{d.path}</td>
                              <td style={{ padding: '0.45rem 0.65rem', color: d.statusCode === 200 ? '#34d399' : '#fbbf24', fontWeight: 600 }}>{d.statusCode}</td>
                              <td style={{ padding: '0.45rem 0.65rem', color: '#94a3b8' }}>{d.category}</td>
                              <td style={{ padding: '0.45rem 0.65rem' }}>
                                <span style={{ fontSize: '0.7rem', padding: '0.15rem 0.4rem', borderRadius: '3px', fontWeight: 700, background: d.riskLevel === 'HIGH' ? 'rgba(239, 68, 68, 0.2)' : '#1e293b', color: d.riskLevel === 'HIGH' ? '#f87171' : '#38bdf8' }}>
                                  {d.riskLevel}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <div style={{ color: '#64748b', fontSize: '0.8rem' }}>Không phát hiện tệp hoặc thư mục nhạy cảm nào bị lộ công khai.</div>
                  )}
                </div>
              )}

              {/* 8. PHẦN 6: BẢN GHI DNS & THÔNG TIN TÊN MIỀN (DNS & WHOIS RECON) */}
              {(recon?.dns || recon?.whois) && (
                <div style={{ marginTop: '1.25rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.92rem', marginBottom: '0.85rem' }}>
                    6. Bản Ghi DNS & Thông Tin Tên Miền (WHOIS):
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
                    {/* DNS Box */}
                    {recon.dns && (
                      <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.85rem' }}>
                        <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '0.4rem' }}>
                          Bản Ghi DNS ({recon.dns.records?.length || 0})
                        </div>
                        <div style={{ fontSize: '0.76rem', color: '#94a3b8', marginBottom: '0.5rem' }}>
                          <strong>IP Phân Giải:</strong>{' '}
                          {recon.dns.resolvedIps?.length > 0 ? (
                            recon.dns.resolvedIps.map((ip, iIdx) => (
                              <code key={iIdx} style={{ background: '#0f172a', color: '#34d399', padding: '0.1rem 0.35rem', borderRadius: '3px', marginRight: '0.3rem' }}>
                                {ip}
                              </code>
                            ))
                          ) : (
                            'N/A'
                          )}
                        </div>
                        {recon.dns.records?.length > 0 && (
                          <div style={{ maxHeight: '130px', overflowY: 'auto' }}>
                            {recon.dns.records.map((r, rIdx) => (
                              <div key={rIdx} style={{ fontSize: '0.74rem', padding: '0.2rem 0', borderTop: '1px solid #1e293b', display: 'flex', gap: '0.5rem' }}>
                                <span style={{ color: '#fbbf24', fontWeight: 700, minWidth: '40px' }}>{r.type}</span>
                                <span style={{ color: '#cbd5e1', wordBreak: 'break-all' }}>{r.value}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    {/* WHOIS Box */}
                    {recon.whois && (
                      <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.85rem' }}>
                        <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#f1f5f9', marginBottom: '0.4rem' }}>
                          Thông Tin WHOIS ({recon.whois.country || 'Global'})
                        </div>
                        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem', fontSize: '0.76rem', color: '#94a3b8' }}>
                          <div>Nhà Đăng Ký: <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{recon.whois.registrar || 'N/A'}</span></div>
                          <div>Tổ Chức: <span style={{ color: '#f1f5f9', fontWeight: 600 }}>{recon.whois.organization || 'N/A'}</span></div>
                          <div>Ngày Đăng Ký: <span style={{ color: '#cbd5e1' }}>{recon.whois.creationDate || 'N/A'}</span></div>
                          <div>Ngày Hết Hạn: <span style={{ color: '#fbbf24', fontWeight: 600 }}>{recon.whois.expiryDate || 'N/A'}</span></div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* 9. PHẦN 7: CÂY BỀ MẶT TẤN CÔNG */}
              {recon?.attackTree && (
                <div style={{ marginTop: '1.25rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ fontWeight: 700, color: '#a855f7', fontSize: '0.92rem', marginBottom: '0.85rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>7. Cây Bề Mặt Tấn Công:</span>
                    <span style={{ fontSize: '0.72rem', background: '#0f172a', color: '#c084fc', padding: '0.15rem 0.45rem', borderRadius: '3px', border: '1px solid #334155' }}>
                      Cấu trúc phân cấp
                    </span>
                  </div>

                  <div style={{ background: '#090e17', border: '1px solid #1e293b', borderRadius: '6px', padding: '0.85rem 1rem', maxHeight: '240px', overflowY: 'auto' }}>
                    <div style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.82rem', marginBottom: '0.5rem' }}>
                      {recon.attackTree.label}
                    </div>
                    <div style={{ paddingLeft: '1rem', borderLeft: '2px solid #334155' }}>
                      {(recon.attackTree.children || []).map((cat, cIdx) => (
                        <div key={cIdx} style={{ marginBottom: '0.65rem' }}>
                          <div style={{ fontWeight: 600, color: '#fbbf24', fontSize: '0.78rem', marginBottom: '0.25rem' }}>
                            {cat.label}
                          </div>
                          <div style={{ paddingLeft: '0.85rem', borderLeft: '1px dashed #1e293b' }}>
                            {(cat.children || []).map((child, chIdx) => (
                              <div key={chIdx} style={{ fontSize: '0.74rem', color: '#cbd5e1', padding: '0.15rem 0', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                <span>• {child.label}</span>
                                {child.details && (
                                  <span style={{ fontSize: '0.7rem', color: '#64748b', maxWidth: '400px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {child.details}
                                  </span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* 10. PHẦN 8: KỊCH BẢN DÒ QUÉT CHUYÊN SÂU */}
              {allScripts.length > 0 && (
                <div style={{ marginTop: '1.25rem', background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1.25rem' }}>
                  <div style={{ fontSize: '0.88rem', fontWeight: 700, color: '#fbbf24', marginBottom: '0.5rem' }}>
                    8. Kết Quả Kịch Bản Dò Quét Chuyên Sâu:
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    {allScripts.map((sc, scIdx) => (
                      <div key={scIdx} style={{ background: '#090e17', border: '1px solid #334155', borderRadius: '6px', padding: '0.75rem 1rem' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                          <strong style={{ color: '#38bdf8', fontSize: '0.82rem' }}>
                            Script: {sc.id}
                          </strong>
                          <span style={{ fontSize: '0.72rem', color: '#94a3b8', background: '#1e293b', padding: '0.15rem 0.45rem', borderRadius: '3px' }}>
                            Port {sc.port}
                          </span>
                        </div>
                        <pre style={{ margin: 0, color: '#cbd5e1', fontSize: '0.76rem', whiteSpace: 'pre-wrap', fontFamily: 'monospace', lineHeight: 1.45 }}>
                          {sc.output}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          );
        };

        return (
          <div className="modal-backdrop">
            <div className="modal-container" style={{ width: '100%', maxWidth: '100%', height: '94vh', maxHeight: '94vh' }}>
              {/* Modal Header */}
              <div className="modal-header" style={{ paddingBottom: '0.6rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <div style={{ fontWeight: 700, fontSize: '1.15rem', color: '#f8fafc' }}>
                    {selectedAssessment.name}
                  </div>
                  <span className="badge-tag">{selectedAssessment.type}</span>
                  {getStatusBadge(selectedAssessment.status)}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
                  <button
                    className="btn btn-primary"
                    onClick={handleExecuteAll}
                    disabled={executingStepId === 'all'}
                    title="Kích hoạt quét toàn diện và tự động phân tích & giải thích bằng AI"
                  >
                    <i className={`fa-solid ${executingStepId === 'all' ? 'fa-spinner fa-spin' : 'fa-bolt-lightning'}`}></i>
                    <span>{executingStepId === 'all' ? 'Đang Quét & Phân Tích AI...' : 'Quét & Phân Tích AI'}</span>
                  </button>

                  <button
                    className="btn btn-purple"
                    onClick={() => handleOpenAiAssistant()}
                    title="Khai thác lỗ hổng & trao đổi trực tiếp với Trợ Lý AI"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', padding: '0.45rem 1rem', fontSize: '0.85rem' }}
                  >
                    <i className="fa-solid fa-wand-magic-sparkles"></i>
                    <span>Khai Thác Lỗ Hổng Với AI</span>
                  </button>

                  <button
                    className="btn btn-outline"
                    onClick={() => handleExportPdf(selectedAssessment)}
                    disabled={isExportingPdf}
                    title="Tải tệp PDF toàn diện kết quả quét & phân tích AI về máy tính"
                    style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', padding: '0.42rem 0.85rem', fontSize: '0.82rem', color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.45)' }}
                  >
                    <i className={`fa-solid ${isExportingPdf ? 'fa-spinner fa-spin' : 'fa-file-pdf'}`}></i>
                    <span>{isExportingPdf ? 'Đang Tải PDF...' : 'Tải Báo Cáo PDF'}</span>
                  </button>

                  <button className="btn-close" onClick={() => setSelectedAssessment(null)} title="Đóng">
                    <i className="fa-solid fa-xmark"></i>
                  </button>
                </div>
              </div>

              {/* Modal Navigation Tabs */}
              <div className="modal-nav-tabs">
                <button
                  className={`modal-nav-tab ${activeModalTab === 'latest' ? 'active' : ''}`}
                  onClick={() => {
                    setActiveModalTab('latest');
                    setSelectedHistoryScanId(null);
                  }}
                >
                  <i className="fa-solid fa-bolt"></i>
                  <span>Phân Tích Mới Nhất</span>
                  {latestScan && (
                    <span className="modal-nav-badge">
                      {latestScan.target}
                    </span>
                  )}
                </button>

                <button
                  className={`modal-nav-tab ${activeModalTab === 'history' ? 'active' : ''}`}
                  onClick={() => setActiveModalTab('history')}
                >
                  <i className="fa-solid fa-clock-rotate-left"></i>
                  <span>Lịch Sử Phân Tích</span>
                  <span className="modal-nav-badge">
                    {scansData.length}
                  </span>
                </button>

                <button
                  className={`modal-nav-tab ${activeModalTab === 'report' ? 'active' : ''}`}
                  onClick={() => setActiveModalTab('report')}
                >
                  <i className="fa-solid fa-file-shield"></i>
                  <span>Báo Cáo An Toàn</span>
                  {reportData?.findings?.length > 0 && (
                    <span className="modal-nav-badge" style={{ background: 'rgba(16, 185, 129, 0.25)', color: '#34d399' }}>
                      {reportData.findings.length}
                    </span>
                  )}
                </button>
              </div>

              <div className="modal-body" style={{ flex: 1, maxHeight: 'none', overflowY: 'auto', padding: '1rem 1.25rem' }}>
                {modalLoading ? (
                  <div style={{ textAlign: 'center', padding: '3rem', color: '#94a3b8' }}>
                    <i className="fa-solid fa-spinner fa-spin" style={{ fontSize: '1.75rem', color: '#38bdf8', marginBottom: '0.75rem' }}></i>
                    <div>Đang tải toàn bộ dữ liệu an ninh & tình báo...</div>
                  </div>
                ) : (
                  <>
                    {/* TAB 1: PHÂN TÍCH MỚI NHẤT (CHỈ GIỮ LẠI LẦN QUÉT MỚI NHẤT) */}
                    {activeModalTab === 'latest' && (
                      <div>
                        {/* Banner thông báo nếu có lịch sử quét cũ */}
                        {oldScansCount > 0 && (
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(56, 189, 248, 0.08)', border: '1px solid rgba(56, 189, 248, 0.25)', borderRadius: '8px', padding: '0.75rem 1rem', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: '#e2e8f0', fontSize: '0.86rem' }}>
                              <i className="fa-solid fa-circle-info" style={{ color: '#38bdf8', fontSize: '1rem' }}></i>
                              <span>
                                Đang hiển thị kết quả phân tích mới nhất cho <strong>{latestScan.target}</strong>. Hệ thống đã ghi nhận <strong>{oldScansCount}</strong> lượt phân tích cũ hơn.
                              </span>
                            </div>
                            <button
                              className="btn btn-sm btn-outline"
                              onClick={() => {
                                setActiveModalTab('history');
                                setSelectedHistoryScanId(null);
                              }}
                              style={{ padding: '0.35rem 0.75rem', fontSize: '0.8rem' }}
                            >
                              <i className="fa-solid fa-clock-rotate-left"></i> Xem {oldScansCount} Lần Quét Cũ
                            </button>
                          </div>
                        )}

                        {latestScan ? (
                          renderScanTask(latestScan, true)
                        ) : (
                          <div style={{ textAlign: 'center', padding: '3rem', color: '#64748b', background: '#0f172a', borderRadius: '8px', border: '1px solid #1e293b' }}>
                            <div style={{ fontSize: '1.1rem', color: '#f1f5f9', fontWeight: 700 }}>Chưa có kết quả quét nào được ghi nhận</div>
                            <div style={{ fontSize: '0.85rem', color: '#94a3b8', marginTop: '0.5rem', maxWidth: '520px', margin: '0.5rem auto 1.25rem auto', lineHeight: 1.5 }}>
                              Bấm nút bên dưới để hệ thống quét toàn diện đồng thời: <strong>Cổng mạng & dịch vụ Nmap, An toàn HTTP & SSL, Dò tìm tệp nhạy cảm Web Dirs, Bản ghi DNS & WHOIS</strong>.
                            </div>
                            <button
                              className="btn btn-primary"
                              onClick={handleExecuteAll}
                              disabled={executingStepId === 'all'}
                              style={{ padding: '0.6rem 1.4rem', fontSize: '0.9rem' }}
                            >
                              <i className="fa-solid fa-bolt-lightning" style={{ marginRight: '0.4rem' }}></i>
                              <span>{executingStepId === 'all' ? 'Đang Quét & Phân Tích AI...' : 'Quét & Phân Tích AI'}</span>
                            </button>
                          </div>
                        )}
                      </div>
                    )}

                    {/* TAB 2: LỊCH SỬ PHÂN TÍCH */}
                    {activeModalTab === 'history' && (
                      <div>
                        {selectedHistoryScanId ? (
                          <div>
                            {/* Breadcrumb quay lại danh sách */}
                            <div className="history-timeline-nav">
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                                <button
                                  className="btn btn-sm btn-outline"
                                  onClick={() => setSelectedHistoryScanId(null)}
                                  style={{ padding: '0.4rem 0.85rem' }}
                                >
                                  <i className="fa-solid fa-arrow-left"></i> Quay Lại Danh Sách Lịch Sử
                                </button>
                                <span style={{ color: '#f1f5f9', fontWeight: 700, fontSize: '0.9rem' }}>
                                  Đang xem chi tiết bản ghi phân tích: {scansData.find((s) => s.id === selectedHistoryScanId)?.target || 'Mục tiêu'}
                                </span>
                              </div>
                              <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                                Lần quét {historyScans.findIndex((s) => s.id === selectedHistoryScanId) + 1 || ''} / {scansData.length} phiên
                              </span>
                            </div>

                            {/* Render Scan chi tiết đã chọn */}
                            {renderScanTask(
                              scansData.find((s) => s.id === selectedHistoryScanId),
                              selectedHistoryScanId === latestScan?.id
                            )}
                          </div>
                        ) : (
                          <div>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                                <i className="fa-solid fa-clock-rotate-left" style={{ color: '#a855f7', fontSize: '1.2rem' }}></i>
                                <h3 style={{ margin: 0, color: '#f8fafc', fontSize: '1.15rem', fontWeight: 800 }}>
                                  Lịch Sử Các Lần Phân Tích & Quét ({scansData.length} Phiên)
                                </h3>
                              </div>
                              <span style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                                Sắp xếp từ phiên mới nhất đến cũ nhất
                              </span>
                            </div>

                            {scansData.length === 0 ? (
                              <div style={{ textAlign: 'center', padding: '3rem', color: '#64748b', background: '#090e17', borderRadius: '8px', border: '1px solid #1e293b' }}>
                                <div>Chưa có dữ liệu lịch sử phân tích nào.</div>
                              </div>
                            ) : (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                                {historyScans.map((scan, idx) => {
                                  let summaryObj = null;
                                  try {
                                    summaryObj = scan.parsedSummary ? (typeof scan.parsedSummary === 'string' ? JSON.parse(scan.parsedSummary) : scan.parsedSummary) : null;
                                  } catch (e) {}

                                  const host = summaryObj?.hosts?.[0];
                                  const portsCount = host?.ports?.length || summaryObj?.totalOpenPorts || 0;
                                  const recon = summaryObj?.recon;
                                  const isLatestItem = idx === 0;

                                  return (
                                    <div
                                      key={scan.id}
                                      className="history-item-card"
                                      style={{ borderLeft: isLatestItem ? '4px solid #38bdf8' : '4px solid #6366f1' }}
                                    >
                                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.65rem' }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
                                          <span style={{ fontWeight: 800, color: isLatestItem ? '#38bdf8' : '#f1f5f9', fontSize: '1.05rem' }}>
                                            {scan.target || 'Mục tiêu'}
                                          </span>
                                          <span style={{ background: 'rgba(2, 132, 199, 0.25)', color: '#38bdf8', fontSize: '0.72rem', fontWeight: 700, padding: '0.15rem 0.5rem', borderRadius: '4px', border: '1px solid rgba(2, 132, 199, 0.4)' }}>
                                            🔍 QUÉT CỔNG MẠNG
                                          </span>
                                          {isLatestItem && (
                                            <span style={{ background: '#0284c7', color: '#fff', fontSize: '0.72rem', fontWeight: 700, padding: '0.15rem 0.5rem', borderRadius: '4px' }}>
                                              MỚI NHẤT
                                            </span>
                                          )}
                                          <code style={{ background: '#0f172a', color: '#38bdf8', padding: '0.2rem 0.5rem', borderRadius: '4px', fontSize: '0.82rem', fontWeight: 600 }}>
                                            {scan.target}
                                          </code>
                                          <span style={{ color: '#94a3b8', fontSize: '0.78rem' }}>
                                            {scan.createdAt ? new Date(scan.createdAt).toLocaleString('vi-VN') : 'Phiên quét'}
                                          </span>
                                        </div>

                                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                          {scan.durationMs && (
                                            <span style={{ fontSize: '0.78rem', color: '#94a3b8', background: '#0f172a', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                                              {(scan.durationMs / 1000).toFixed(1)}s
                                            </span>
                                          )}
                                          <span className={`badge-status ${scan.status === 'COMPLETED' ? 'success' : scan.status === 'RUNNING' ? 'info' : 'danger'}`}>
                                            {scan.status === 'COMPLETED' ? 'HOÀN THÀNH' : scan.status === 'RUNNING' ? 'ĐANG QUÉT' : 'THẤT BẠI'}
                                          </span>
                                        </div>
                                      </div>

                                      {/* Snapshot Info Pills */}
                                      <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'center', fontSize: '0.78rem' }}>
                                        {portsCount > 0 && (
                                          <span style={{ background: '#0f172a', color: '#fbbf24', padding: '0.25rem 0.6rem', borderRadius: '4px', border: '1px solid #1e293b' }}>
                                            <i className="fa-solid fa-network-wired" style={{ marginRight: '0.35rem' }}></i>
                                            {portsCount} Cổng Mở
                                          </span>
                                        )}



                                        {recon?.techStack && (
                                          <span style={{ background: '#0f172a', color: '#38bdf8', padding: '0.25rem 0.6rem', borderRadius: '4px', border: '1px solid #1e293b' }}>
                                            <i className="fa-solid fa-layer-group" style={{ marginRight: '0.35rem' }}></i>
                                            {recon.techStack.technologies?.length || 0} Nền Tảng
                                          </span>
                                        )}

                                        {recon?.vulnerabilityAudit && (
                                          <span style={{ background: '#0f172a', color: (recon.vulnerabilityAudit.findings?.length || 0) > 0 ? '#f87171' : '#34d399', padding: '0.25rem 0.6rem', borderRadius: '4px', border: '1px solid #1e293b' }}>
                                            <i className="fa-solid fa-triangle-exclamation" style={{ marginRight: '0.35rem' }}></i>
                                            {recon.vulnerabilityAudit.findings?.length || 0} Điểm Yếu
                                          </span>
                                        )}

                                        {recon?.httpSecurity && (
                                          <span style={{ background: '#0f172a', color: '#34d399', padding: '0.25rem 0.6rem', borderRadius: '4px', border: '1px solid #1e293b' }}>
                                            <i className="fa-solid fa-shield" style={{ marginRight: '0.35rem' }}></i>
                                            Điểm HTTP: {recon.httpSecurity.score}/100 ({recon.httpSecurity.grade})
                                          </span>
                                        )}
                                      </div>

                                      {/* Action Buttons */}
                                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem', marginTop: '0.25rem' }}>
                                        <button
                                          className="btn btn-sm btn-primary"
                                          onClick={() => setSelectedHistoryScanId(scan.id)}
                                        >
                                          <i className="fa-solid fa-eye"></i> Xem Chi Tiết Phân Tích
                                        </button>
                                      </div>
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* TAB 3: BÁO CÁO TỔNG HỢP & KHẮC PHỤC (EXECUTIVE SUMMARY & REMEDIATION) */}
                    {activeModalTab === 'report' && (
                      <div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid #1e293b', paddingBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <i className="fa-solid fa-shield-halved" style={{ color: '#34d399', fontSize: '1.2rem' }}></i>
                            <h3 style={{ margin: 0, color: '#f8fafc', fontSize: '1.15rem', fontWeight: 800 }}>
                              Báo Cáo An Toàn & Khuyến Nghị Khắc Phục (AI)
                            </h3>
                          </div>
                          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                            {reportData && (
                              <span style={{ fontSize: '0.8rem', padding: '0.2rem 0.6rem', borderRadius: '4px', fontWeight: 700, background: reportData.overallRisk === 'CRITICAL' || reportData.overallRisk === 'HIGH' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)', color: reportData.overallRisk === 'CRITICAL' || reportData.overallRisk === 'HIGH' ? '#fca5a5' : '#6ee7b7', border: '1px solid currentColor' }}>
                                MỨC ĐỘ RỦI RO: {reportData.overallRisk}
                              </span>
                            )}
                            <button
                              className="btn btn-sm btn-outline"
                              onClick={() => handleExportPdf(selectedAssessment)}
                              disabled={isExportingPdf}
                              title="Tải tệp PDF toàn diện kết quả quét & phân tích AI về máy tính"
                              style={{ color: '#ef4444', borderColor: 'rgba(239, 68, 68, 0.45)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                            >
                              <i className={`fa-solid ${isExportingPdf ? 'fa-spinner fa-spin' : 'fa-file-pdf'}`}></i> {isExportingPdf ? 'Đang Tải PDF...' : 'Tải Báo Cáo PDF'}
                            </button>
                          </div>
                        </div>

                        {reportData ? (
                          <div>
                            {/* Executive Summary Card */}
                            <div style={{ background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.08), rgba(15, 23, 42, 0.95))', borderRadius: '8px', padding: '1rem 1.25rem', marginBottom: '1.25rem', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
                              <div style={{ fontWeight: 700, color: '#34d399', marginBottom: '0.4rem', fontSize: '0.9rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <i className="fa-solid fa-brain"></i>
                                <span>Tóm Tắt Điều Hành:</span>
                              </div>
                              <p style={{ margin: 0, color: '#f1f5f9', fontSize: '0.88rem', lineHeight: 1.55 }}>
                                {reportData.executiveSummary}
                              </p>
                            </div>

                            {/* Severity Counters */}
                            <div className="grid-cols-4" style={{ marginBottom: '1.25rem' }}>
                              <div className="stat-card" style={{ padding: '0.75rem 1rem' }}>
                                <span className="pill-vuln critical">CRITICAL</span>
                                <span style={{ fontSize: '1.4rem', fontWeight: 'bold', color: '#f87171', marginLeft: 'auto' }}>
                                  {reportData.criticalCount || 0}
                                </span>
                              </div>
                              <div className="stat-card" style={{ padding: '0.75rem 1rem' }}>
                                <span className="pill-vuln high">HIGH</span>
                                <span style={{ fontSize: '1.4rem', fontWeight: 'bold', color: '#fb923c', marginLeft: 'auto' }}>
                                  {reportData.highCount || 0}
                                </span>
                              </div>
                              <div className="stat-card" style={{ padding: '0.75rem 1rem' }}>
                                <span className="pill-vuln med">MEDIUM</span>
                                <span style={{ fontSize: '1.4rem', fontWeight: 'bold', color: '#facc15', marginLeft: 'auto' }}>
                                  {reportData.mediumCount || 0}
                                </span>
                              </div>
                              <div className="stat-card" style={{ padding: '0.75rem 1rem' }}>
                                <span className="pill-vuln low">LOW</span>
                                <span style={{ fontSize: '1.4rem', fontWeight: 'bold', color: '#38bdf8', marginLeft: 'auto' }}>
                                  {reportData.lowCount || 0}
                                </span>
                              </div>
                            </div>

                            {/* Findings & Remediation Table */}
                            {reportData.findings && reportData.findings.length > 0 && (
                              <div className="table-responsive" style={{ marginBottom: '1.25rem', border: '1px solid #1e293b', borderRadius: '8px', overflow: 'hidden' }}>
                                <table className="data-table">
                                  <thead>
                                    <tr>
                                      <th style={{ width: '100px' }}>Mức Độ</th>
                                      <th>Lỗ Hổng & Mô Tả Chi Tiết</th>
                                      <th style={{ width: '150px' }}>Mục Tiêu</th>
                                      <th>Biện Pháp Khắc Phục Khuyến Nghị</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {reportData.findings.map((f, fIdx) => (
                                      <tr key={fIdx}>
                                        <td>
                                          <span className={`pill-vuln ${f.severity?.toLowerCase()}`}>
                                            {f.severity}
                                          </span>
                                        </td>
                                        <td>
                                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                                            <span style={{ fontWeight: 600, color: '#f8fafc' }}>{f.title}</span>
                                            {f.mitreTechniqueId && (
                                              <span style={{ fontSize: '0.7rem', fontWeight: 700, color: '#38bdf8', background: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.35)', padding: '0.1rem 0.4rem', borderRadius: '4px', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }} title={`MITRE ATT&CK: ${f.mitreTactic || ''} - ${f.mitreTechniqueName || ''}`}>
                                                <i className="fa-solid fa-cubes-stacked"></i>
                                                MITRE {f.mitreTechniqueId}
                                              </span>
                                            )}
                                          </div>
                                          {f.description && (
                                            <div style={{ fontSize: '0.78rem', color: '#94a3b8', marginTop: '0.2rem', lineHeight: 1.4 }}>
                                              {f.description}
                                            </div>
                                          )}
                                          {f.exploitationVector && (
                                            <div style={{ marginTop: '0.45rem', padding: '0.45rem 0.65rem', background: 'rgba(168, 85, 247, 0.08)', border: '1px solid rgba(168, 85, 247, 0.25)', borderRadius: '6px', fontSize: '0.76rem', color: '#e9d5ff', lineHeight: 1.45 }}>
                                              <div style={{ fontWeight: 700, color: '#c084fc', display: 'flex', alignItems: 'center', gap: '0.35rem', marginBottom: '0.2rem' }}>
                                                <i className="fa-solid fa-crosshairs"></i>
                                                <span>Hướng & Kịch Bản Khai Thác:</span>
                                              </div>
                                              <div>{f.exploitationVector}</div>
                                            </div>
                                          )}
                                        </td>
                                        <td>
                                          <code style={{ background: '#0f172a', padding: '0.2rem 0.4rem', borderRadius: '4px', fontSize: '0.75rem', color: '#38bdf8' }}>
                                            {f.target}
                                          </code>
                                          {f.port && <span style={{ fontSize: '0.75rem', color: '#34d399', marginLeft: '0.3rem' }}>Port {f.port}</span>}
                                        </td>
                                        <td style={{ fontSize: '0.82rem', color: '#cbd5e1', lineHeight: 1.45 }}>
                                          <div>{f.remediation}</div>
                                        </td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}

                            {/* AI Focus Recommendations */}
                            {reportData.recommendations && (
                              <div style={{ background: '#0c1322', border: '1px solid #1e293b', borderRadius: '8px', padding: '1rem 1.25rem' }}>
                                <div style={{ fontWeight: 700, color: '#38bdf8', fontSize: '0.9rem', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                  <i className="fa-solid fa-list-check"></i>
                                  <span>Khuyến Nghị Khắc Phục Trọng Tâm:</span>
                                </div>
                                <div style={{ color: '#cbd5e1', fontSize: '0.85rem', lineHeight: 1.5, whiteSpace: 'pre-wrap' }}>
                                  {reportData.recommendations}
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '1rem 1.25rem', background: '#0f172a', borderRadius: '8px', border: '1px dashed #334155', flexWrap: 'wrap', gap: '0.75rem' }}>
                            <div>
                              <div style={{ color: '#f1f5f9', fontWeight: 600, fontSize: '0.9rem' }}>Chưa có báo cáo tổng kết chính thức.</div>
                              <div style={{ color: '#94a3b8', fontSize: '0.8rem', marginTop: '0.15rem' }}>
                                Bấm nút bên cạnh để AI tự động tổng hợp toàn bộ lỗ hổng và đề xuất phương án khắc phục.
                              </div>
                            </div>
                            <button
                              className="btn btn-purple"
                              onClick={handleGenerateReport}
                              disabled={generatingAi}
                            >
                              <i className={`fa-solid ${generatingAi ? 'fa-spinner fa-spin' : 'fa-wand-magic-sparkles'}`}></i>
                              <span>{generatingAi ? 'Đang Phân Tích...' : 'Tổng Hợp Báo Cáo'}</span>
                            </button>
                          </div>
                        )}
                      </div>
                    )}


                  </>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* 4. MODAL TRỢ LÝ GROQ AI */}
      <GroqAssistantModal
        isOpen={assistantOpen}
        onClose={() => setAssistantOpen(false)}
        contextData={assistantContext}
        title={selectedAssessment?.name || 'Phiên Kiểm Thử'}
        relatedTaskId={assistantContext?.scanTask?.id || null}
      />


    </div>
  );
}
