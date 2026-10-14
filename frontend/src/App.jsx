import React, { useState } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import ToastNotification from './components/ToastNotification';
import GroqAssistantModal from './components/GroqAssistantModal';
import AssessmentsView from './views/AssessmentsView';
import CreateAssessmentView from './views/CreateAssessmentView';
import AuditLogsView from './views/AuditLogsView';
import SecurityConfigView from './views/SecurityConfigView';
import ChatbotAiView from './views/ChatbotAiView';
import BloodhoundAdAuditView from './components/BloodhoundAdAuditView';
import MitreAttackView from './views/MitreAttackView';

export default function App() {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [activeTab, setActiveTab] = useState('assessments');
  const [globalAiOpen, setGlobalAiOpen] = useState(false);
  const [globalAiContext, setGlobalAiContext] = useState(null);

  const handleOpenGlobalAi = (context = null) => {
    if (context && typeof context === 'object' && context.prompt) {
      // Khi nhấn "Gửi Sang Chatbot AI" từ BloodHound hoặc các màn hình kiểm thử:
      // Lưu prompt để ChatbotAiView tự động gửi ngay khi nạp và chuyển sang tab chatbot
      sessionStorage.setItem('attt_pending_chat_prompt', JSON.stringify({
        prompt: context.prompt,
        shortLabel: context.shortLabel || 'Phân tích dữ liệu Active Directory thực tế và hướng dẫn BƯỚC 1'
      }));
      // Lưu đồng bộ thông tin xác thực vào localStorage để Chatbot tự động nạp vào context
      if (context.bloodhoundData || context.domain || context.username) {
        try {
          const prev = JSON.parse(localStorage.getItem('attt_bloodhound_audit_data') || '{}');
          localStorage.setItem('attt_bloodhound_audit_data', JSON.stringify({
            ...prev,
            domain: context.domain || context.bloodhoundData?.domainName || prev.domain || '',
            host: context.host || context.bloodhoundData?.host || prev.host || '',
            authenticatedUser: context.username || context.bloodhoundData?.authenticatedUser || prev.authenticatedUser || '',
            password: context.password || context.bloodhoundData?.password || prev.password || '',
            hasValidCredentials: true,
            summary: context.bloodhoundData || prev.summary,
            scannedAt: new Date().toISOString()
          }));
        } catch (e) {}
      }
      setActiveTab('chatbot');
      return;
    }
    setGlobalAiContext(context);
    setGlobalAiOpen(true);
  };

  return (
    <div className="app-container">
      {/* Toast thông báo lỗi / thành công tập trung từ Axios Interceptor */}
      <ToastNotification />

      {/* 1. Sidebar bên trái */}
      <Sidebar 
        isCollapsed={isCollapsed} 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
      />

      {/* Khung chính chứa Header và Content Area */}
      <div className="main-wrapper">
        {/* 2. Header trên cùng */}
        <Header 
          isCollapsed={isCollapsed} 
          setIsCollapsed={setIsCollapsed} 
          activeTab={activeTab} 
        />

        {/* 3. Content Area hiển thị động */}
        <main className="content-area">
          {activeTab === 'assessments' && <AssessmentsView setActiveTab={setActiveTab} />}
          {activeTab === 'mitre' && (
            <MitreAttackView setActiveTab={setActiveTab} onAskAi={(ctx) => handleOpenGlobalAi(ctx)} />
          )}
          {activeTab === 'bloodhound' && (
            <BloodhoundAdAuditView onAskAi={(ctx) => handleOpenGlobalAi(ctx)} />
          )}
          {activeTab === 'create-assessment' && (
            <CreateAssessmentView
              onCreated={() => setActiveTab('assessments')}
              onCancel={() => setActiveTab('assessments')}
            />
          )}
          {activeTab === 'chatbot' && <ChatbotAiView />}
          {activeTab === 'logs' && <AuditLogsView />}
          {activeTab === 'security' && <SecurityConfigView />}
        </main>
      </div>

      {/* 4. Nút Floating Chat AI kích hoạt nhanh toàn cục */}
      <button
        className="floating-ai-trigger-btn"
        onClick={() => handleOpenGlobalAi('Hệ Thống Đánh Giá & Giám Sát An Toàn Thông Tin T9')}
        title="Mở Trợ Lý An Ninh Mạng AI"
      >
        <div className="floating-ai-glow"></div>
        <i className="fa-solid fa-wand-magic-sparkles"></i>
        <span className="floating-ai-text">Trợ Lý AI</span>
        <span className="floating-ai-badge">Online</span>
      </button>

      {/* Modal Chat AI Toàn Cục */}
      <GroqAssistantModal
        isOpen={globalAiOpen}
        onClose={() => setGlobalAiOpen(false)}
        contextData={globalAiContext || 'Hệ Thống Đánh Giá & Giám Sát An Toàn Thông Tin T9'}
        title="Trợ Lý Phân Tích & Cố Vấn An Ninh AI"
      />
    </div>
  );
}

