import React, { useState, useEffect } from 'react';
import apiClient, { toastEmitter } from '../services/api';

export default function SecurityConfigView() {
  const [policyConfig, setPolicyConfig] = useState({
    allowedTools: ['nmap'],
    maxTimeoutSeconds: 600,
    defaultTimeoutSeconds: 180,
    maxConcurrentTasks: 4,
    maxMemoryMb: 512,
    maxOutputSizeKb: 10240,
    enforceApproval: true,
  });

  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchConfig();
  }, []);

  const fetchConfig = async () => {
    try {
      setLoading(true);
      const res = await apiClient.get('/policy/config');
      if (res) {
        setPolicyConfig(res);
      }
    } catch (err) {
      console.log('Using default policy config');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      const res = await apiClient.put('/policy/config', policyConfig);
      if (res) {
        setPolicyConfig(res);
      }
      toastEmitter.show('Đã lưu', 'Chính sách an toàn đã được cập nhật thành công trên máy chủ.', 'success');
    } catch (err) {
      toastEmitter.show('Lỗi', err?.message || 'Không thể cập nhật chính sách an toàn.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card-panel">
      <div className="card-title-row">
        <div className="card-title">
          <i className="fa-solid fa-shield-halved" style={{ color: '#38bdf8' }}></i>
          Chính Sách An Toàn & Giới Hạn Hệ Thống
        </div>
        <button className="btn btn-outline" onClick={fetchConfig} disabled={loading}>
          <i className={`fa-solid fa-arrows-rotate ${loading ? 'fa-spin' : ''}`}></i> Đồng bộ
        </button>
      </div>

      {/* Bảng quy tắc an toàn */}
      <div style={{ marginBottom: '1.5rem' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '25%' }}>Quy Tắc Kiểm Soát</th>
              <th style={{ width: '50%' }}>Mô Tả Áp Dụng</th>
              <th style={{ width: '25%' }}>Trạng Thái</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td><strong>Giới Hạn Phạm Vi</strong></td>
              <td>Chỉ quét IP/CIDR/Domain nằm trong danh sách Whitelist cho phép.</td>
              <td><span className="badge-status success">Hoạt Động</span></td>
            </tr>
            <tr>
              <td><strong>Danh Sách Trắng Công Cụ</strong></td>
              <td>Chỉ cho phép công cụ <code>{(policyConfig.allowedTools || ['nmap']).join(', ')}</code> với các profile quét đã định nghĩa.</td>
              <td><span className="badge-status success">Khóa Cứng</span></td>
            </tr>
            <tr>
              <td><strong>Cơ Chế Phê Duyệt</strong></td>
              <td>Hành động tác động mức Medium/High/Critical {policyConfig.enforceApproval ? 'bắt buộc chuyên viên duyệt' : 'tự động thực thi'}.</td>
              <td><span className={`badge-status ${policyConfig.enforceApproval ? 'warning' : 'info'}`}>{policyConfig.enforceApproval ? 'Bắt Buộc Duyệt' : 'Tự Động'}</span></td>
            </tr>
            <tr>
              <td><strong>Giới Hạn Tài Nguyên</strong></td>
              <td>Timeout tối đa ({policyConfig.maxTimeoutSeconds}s), RAM ({policyConfig.maxMemoryMb}MB), Output ({Math.round(policyConfig.maxOutputSizeKb / 1024)}MB).</td>
              <td><span className="badge-status info">Giám Sát</span></td>
            </tr>
            <tr>
              <td><strong>Nhật Ký Toàn Vẹn</strong></td>
              <td>Lưu vết toàn bộ yêu cầu, người gọi và quyết định vào bảng <code>audit_logs</code>.</td>
              <td><span className="badge-status success">Ghi Vết</span></td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Tham số thực thi */}
      <div className="card-title-row" style={{ marginTop: '1.25rem', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '1.25rem' }}>
        <div className="card-title" style={{ fontSize: '0.95rem' }}>
          <i className="fa-solid fa-sliders" style={{ color: '#10b981' }}></i>
          Tham Số Thực Thi
        </div>
      </div>

      <form onSubmit={handleSave} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem', marginTop: '0.75rem' }}>
        <div className="form-group">
          <label className="form-label">Timeout Mặc Định Giây</label>
          <input
            type="number"
            className="form-control"
            value={policyConfig.defaultTimeoutSeconds}
            onChange={(e) => setPolicyConfig({ ...policyConfig, defaultTimeoutSeconds: parseInt(e.target.value) || 180 })}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Timeout Tối Đa Giây</label>
          <input
            type="number"
            className="form-control"
            value={policyConfig.maxTimeoutSeconds}
            onChange={(e) => setPolicyConfig({ ...policyConfig, maxTimeoutSeconds: parseInt(e.target.value) || 600 })}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Giới Hạn Bộ Nhớ MB</label>
          <input
            type="number"
            className="form-control"
            value={policyConfig.maxMemoryMb}
            onChange={(e) => setPolicyConfig({ ...policyConfig, maxMemoryMb: parseInt(e.target.value) || 512 })}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Kích Thước Output Tối Đa KB</label>
          <input
            type="number"
            className="form-control"
            value={policyConfig.maxOutputSizeKb}
            onChange={(e) => setPolicyConfig({ ...policyConfig, maxOutputSizeKb: parseInt(e.target.value) || 10240 })}
          />
        </div>

        <div className="form-group" style={{ gridColumn: 'span 2' }}>
          <label className="form-label">Allowlist Công Cụ</label>
          <input
            type="text"
            className="form-control"
            value={(policyConfig.allowedTools || ['nmap']).join(', ')}
            disabled
          />
        </div>

        <div style={{ gridColumn: 'span 2', display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
          <button type="submit" className="btn btn-primary" disabled={loading}>
            <i className={`fa-solid ${loading ? 'fa-spinner fa-spin' : 'fa-floppy-disk'}`}></i>
            {loading ? ' Đang lưu...' : ' Lưu Cấu Hình'}
          </button>
        </div>
      </form>
    </div>
  );
}
