import React, { useState, useEffect } from 'react';
import { authStorage } from '../services/api';

export default function Sidebar({ isCollapsed, activeTab, setActiveTab }) {
  const [user, setUser] = useState(authStorage.getUser());

  useEffect(() => {
    const handleAuthChange = () => setUser(authStorage.getUser());
    window.addEventListener('auth-change', handleAuthChange);
    return () => window.removeEventListener('auth-change', handleAuthChange);
  }, []);

  const menuItems = [
    { id: 'assessments', title: 'Đánh Giá & Kiểm Thử', icon: 'fa-solid fa-shield-halved', category: 'KIỂM THỬ' },
    { id: 'mitre', title: 'MITRE ATT&CK', icon: 'fa-solid fa-cubes-stacked', category: 'KIỂM THỬ' },
    { id: 'bloodhound', title: 'Active Directory', icon: 'fa-solid fa-network-wired', category: 'KIỂM THỬ' },
    { id: 'chatbot', title: 'Trợ Lý AI', icon: 'fa-solid fa-wand-magic-sparkles', category: 'TRỢ LÝ' },
    { id: 'logs', title: 'Nhật Ký', icon: 'fa-solid fa-clipboard-list', category: 'HỆ THỐNG' },
    { id: 'security', title: 'Cấu Hình', icon: 'fa-solid fa-sliders', category: 'HỆ THỐNG' },
  ];

  let currentCategory = null;

  return (
    <aside className={`sidebar ${isCollapsed ? 'collapsed' : ''}`}>
      <div className="sidebar-header">
        <a 
          href="#" 
          className="brand-logo" 
          onClick={(e) => { e.preventDefault(); setActiveTab('assessments'); }}
        >
          <div className="brand-icon">
            <i className="fa-solid fa-shield-virus"></i>
          </div>
          <div className="brand-text">
            ATTT PORTAL
          </div>
        </a>
      </div>

      <ul className="sidebar-menu">
        {menuItems.map((item) => {
          const showCategory = item.category !== currentCategory;
          if (showCategory) currentCategory = item.category;

          return (
            <React.Fragment key={item.id}>
              {showCategory && <div className="menu-category">{item.category}</div>}
              <li
                className={`menu-item ${activeTab === item.id ? 'active' : ''}`}
                onClick={() => setActiveTab(item.id)}
                title={isCollapsed ? item.title : ''}
              >
                <i className={`${item.icon} menu-icon`}></i>
                <span className="menu-title">{item.title}</span>
                {item.badge && <span className="badge-tag">{item.badge}</span>}
              </li>
            </React.Fragment>
          );
        })}
      </ul>

      <div className="sidebar-footer">
        <div className="user-avatar-sm">
          <i className="fa-solid fa-shield-halved"></i>
        </div>
        <div className="user-info-text">
          <div className="user-name">ATTT Portal</div>
          <div className="user-role" style={{ color: '#10b981' }}>● Sẵn sàng</div>
        </div>
      </div>
    </aside>
  );
}
