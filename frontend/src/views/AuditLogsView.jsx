import React, { useState, useEffect } from 'react';
import apiClient, { toastEmitter } from '../services/api';

export default function AuditLogsView() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchAuditLogs();
  }, []);

  const fetchAuditLogs = async () => {
    try {
      setLoading(true);
      const res = await apiClient.get('/audit-logs');
      const data = Array.isArray(res) ? res : res?.data || [];
      setLogs(data);
    } catch (err) {
      setLogs([]);
      toastEmitter.show('Lỗi tải nhật ký', 'Không thể kết nối đến máy chủ để lấy nhật ký kiểm toán.', 'error');
    } finally {
      setLoading(false);
    }
  };

  const filteredLogs = logs.filter((log) => {
    const term = searchTerm.toLowerCase();
    return (
      log.requester?.toLowerCase().includes(term) ||
      log.action?.toLowerCase().includes(term) ||
      log.moduleName?.toLowerCase().includes(term) ||
      log.target?.toLowerCase().includes(term) ||
      log.decision?.toLowerCase().includes(term)
    );
  });

  return (
    <div className="card-panel">
      <div className="card-title-row">
        <div className="card-title">
          <i className="fa-solid fa-list-check" style={{ color: '#6366f1' }}></i>
          Nhật Ký Kiểm Toán (Audit Logs)
        </div>
        <button
          className="btn btn-outline"
          onClick={() => {
            fetchAuditLogs();
            toastEmitter.show('Làm mới', 'Đã cập nhật nhật ký kiểm toán.', 'success');
          }}
        >
          <i className={`fa-solid fa-arrows-rotate ${loading ? 'fa-spin' : ''}`}></i> Làm mới
        </button>
      </div>

      <div style={{ marginBottom: '1.25rem' }}>
        <div className="search-box" style={{ maxWidth: '420px' }}>
          <i className="fa-solid fa-magnifying-glass" style={{ color: '#38bdf8', fontSize: '0.9rem' }}></i>
          <input
            type="text"
            placeholder="Tìm theo người dùng, hành động, module, IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button
              type="button"
              onClick={() => setSearchTerm('')}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '0.2rem', display: 'flex', alignItems: 'center' }}
              title="Xóa tìm kiếm"
            >
              <i className="fa-solid fa-xmark"></i>
            </button>
          )}
        </div>
      </div>

      <div className="table-responsive">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '60px' }}>STT</th>
              <th>Người Thực Hiện</th>
              <th>Hành Động</th>
              <th>Module</th>
              <th>Mục Tiêu</th>
              <th>Quyết Định</th>
              <th>Kết Quả</th>
              <th>Thời Gian</th>
            </tr>
          </thead>
          <tbody>
            {filteredLogs.length === 0 ? (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', padding: '2rem', color: '#64748b' }}>
                  Chưa có bản ghi nhật ký nào.
                </td>
              </tr>
            ) : (
              filteredLogs.map((log, idx) => (
                <tr key={log.id}>
                  <td style={{ color: '#64748b' }}>{idx + 1}</td>
                  <td style={{ color: '#f8fafc', fontWeight: '500' }}>{log.requester}</td>
                  <td><code>{log.action}</code></td>
                  <td>
                    <span className="badge-method get" style={{ textTransform: 'uppercase' }}>
                      {log.moduleName}
                    </span>
                  </td>
                  <td><code>{log.target || 'N/A'}</code></td>
                  <td>
                    <span className={`badge-status ${log.decision === 'ALLOWED' || log.decision === 'APPROVED' || log.decision === 'EXECUTED' ? 'success' : 'danger'}`}>
                      {log.decision}
                    </span>
                  </td>
                  <td>
                    <span className={`badge-status ${log.resultStatus === 'SUCCESS' ? 'success' : log.resultStatus === 'BLOCKED' || log.resultStatus === 'TIMEOUT' ? 'danger' : 'warning'}`}>
                      {log.resultStatus}
                    </span>
                    {log.errorMessage && (
                      <div style={{ fontSize: '0.75rem', color: '#f87171', marginTop: '0.2rem' }}>
                        {log.errorMessage}
                      </div>
                    )}
                  </td>
                  <td style={{ color: '#94a3b8', fontSize: '0.82rem' }}>
                    {log.createdAt ? new Date(log.createdAt).toLocaleTimeString('vi-VN') + ' ' + new Date(log.createdAt).toLocaleDateString('vi-VN') : 'N/A'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
