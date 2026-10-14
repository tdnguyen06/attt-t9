import React from 'react';
import { toastEmitter } from '../services/api';

export default function Header({ isCollapsed, setIsCollapsed, activeTab }) {
  const getTabTitle = () => {
    switch (activeTab) {
      case 'assessments': return 'Đánh Giá & Kiểm Thử';
      case 'mitre': return 'Khung MITRE ATT&CK';
      case 'bloodhound': return 'Active Directory Audit';
      case 'create-assessment': return 'Tạo Đợt Đánh Giá';
      case 'chatbot': return 'Trợ Lý AI';
      case 'logs': return 'Nhật Ký Kiểm Toán';
      case 'security': return 'Chính Sách & Cấu Hình';
      default: return 'Đánh Giá & Kiểm Thử';
    }
  };

  const title = getTabTitle();

  return (
    <header className="header">
      <div className="header-left">
        <button 
          className="toggle-btn" 
          onClick={() => setIsCollapsed(!isCollapsed)}
          title="Thu gọn / Mở rộng Menu"
        >
          <i className={`fa-solid ${isCollapsed ? 'fa-indent' : 'fa-outdent'}`}></i>
        </button>
        <div className="page-breadcrumb">
          <div className="page-title">{title}</div>
        </div>
      </div>

      <div className="header-right">
        <div className="status-pill" title="Hệ thống giám sát đang hoạt động ổn định">
          <div className="pulse-dot"></div>
          <span>Hệ Thống: Trực Tuyến</span>
        </div>

        <button 
          className="header-action-btn"
          onClick={() => toastEmitter.show('Thông báo hệ thống', 'Hệ thống an toàn thông tin đang hoạt động ổn định.', 'info')}
          title="Thông báo"
        >
          <i className="fa-regular fa-bell"></i>
        </button>
      </div>
    </header>
  );
}
