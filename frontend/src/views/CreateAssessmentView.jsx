import React, { useState } from 'react';
import { toastEmitter, apiClient } from '../services/api';

export default function CreateAssessmentView({ onCreated, onCancel }) {
  const [formData, setFormData] = useState({
    name: '',
    type: 'SERVER',
    target: '',
    excludedTarget: '',
    description: '',
  });

  const [errors, setErrors] = useState({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  const validate = () => {
    const errs = {};
    if (!formData.name.trim()) {
      errs.name = 'Vui lòng nhập tên cuộc đánh giá';
    } else if (formData.name.trim().length < 3) {
      errs.name = 'Tối thiểu 3 ký tự';
    }

    if (!formData.target.trim()) {
      errs.target = 'Vui lòng nhập ít nhất một mục tiêu';
    }

    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate()) {
      toastEmitter.show('Dữ liệu chưa hợp lệ', 'Vui lòng kiểm tra lại các trường bắt buộc.', 'warning');
      return;
    }

    setIsSubmitting(true);

    const targetsList = formData.target
      .split(/[\n,]+/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0);

    const excludedList = formData.excludedTarget
      ? formData.excludedTarget
          .split(/[\n,]+/)
          .map((t) => t.trim())
          .filter((t) => t.length > 0)
      : [];

    const isAnyUrl = targetsList.some((t) => t.startsWith('http://') || t.startsWith('https://'));
    const finalType = isAnyUrl ? 'WEB' : formData.type;

    const payload = {
      name: formData.name.trim(),
      type: finalType,
      description: formData.description.trim() || `Đánh giá toàn diện ${formData.name}`,
      createdBy: 'Chuyên viên ATTT',
      targets: targetsList,
      excludedTargets: excludedList,
    };

    try {
      const response = await apiClient.post('/assessments', payload);
      const newAssessment = response;
      if (!newAssessment || !newAssessment.id) {
        throw new Error('Máy chủ không trả về phiên đánh giá hợp lệ.');
      }

      // TỰ ĐỘNG LẬP KẾ HOẠCH, PHÊ DUYỆT VÀ KÍCH HOẠT QUÉT TOÀN BỘ BẰNG AI (ALL-IN-ONE)
      try {
        await apiClient.post(`/plans/generate/${newAssessment.id}`);
        await apiClient.post(`/plans/assessment/${newAssessment.id}/approve-all`, {
          approvedBy: 'Chuyên viên ATTT',
        });
        await apiClient.post(`/plans/assessment/${newAssessment.id}/execute-all`, {
          executedBy: 'Chuyên viên ATTT',
        });
      } catch (autoErr) {
        console.warn('Auto execution notice:', autoErr);
      }

      toastEmitter.show(
        'Khởi tạo & Phân tích thành công',
        `Đã tạo phiên "${formData.name}". Hệ thống đang tự động rà quét và phân tích bằng AI!`,
        'success'
      );

      if (onCreated) {
        onCreated(newAssessment);
      }
    } catch (err) {
      toastEmitter.show('Lỗi khởi tạo', err?.message || 'Không thể tạo mới phiên đánh giá.', 'error');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="card-panel" style={{ maxWidth: '880px', margin: '1rem auto', padding: '2.5rem' }}>
      <div className="card-title-row" style={{ marginBottom: '2rem', paddingBottom: '1rem' }}>
        <div className="card-title" style={{ fontSize: '1.25rem' }}>
          Tạo Đợt Đánh Giá An Toàn Toàn Diện
        </div>
        <button className="btn btn-outline" onClick={onCancel} disabled={isSubmitting}>
          <i className="fa-solid fa-arrow-left"></i> Quay lại
        </button>
      </div>

      <form onSubmit={handleSubmit}>
        <div className="form-group" style={{ marginBottom: '1.75rem' }}>
          <label className="form-label required">Tên Cuộc Đánh Giá</label>
          <input
            type="text"
            className={`form-control ${errors.name ? 'is-invalid' : ''}`}
            placeholder="Ví dụ: Rà soát toàn diện Cổng Thông Tin Sinh Viên"
            value={formData.name}
            onChange={(e) => setFormData({ ...formData, name: e.target.value })}
            disabled={isSubmitting}
            style={{ padding: '0.9rem 1.15rem' }}
          />
          {errors.name && <div className="form-error">{errors.name}</div>}
        </div>

        <div className="grid-cols-2" style={{ gap: '1.75rem', marginBottom: '1.75rem' }}>
          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label required">Loại Hình Kiểm Thử</label>
            <select
              className="form-control"
              value={formData.type}
              onChange={(e) => setFormData({ ...formData, type: e.target.value })}
              disabled={isSubmitting}
              style={{ padding: '0.9rem 1.15rem' }}
            >
              <option value="SERVER">Máy Chủ / Hạ Tầng Mạng</option>
              <option value="WEB">Ứng Dụng Web / Dịch Vụ API</option>
            </select>
          </div>

          <div className="form-group" style={{ marginBottom: 0 }}>
            <label className="form-label">Chế Độ Quét</label>
            <div
              style={{
                padding: '0.85rem 1.15rem',
                background: 'rgba(56, 189, 248, 0.08)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                borderRadius: '8px',
                color: '#38bdf8',
                fontSize: '0.86rem',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
              }}
            >
              <span>Quét Toàn Diện Tất Cả</span>
            </div>
          </div>
        </div>

        <div className="form-group" style={{ marginBottom: '1.75rem' }}>
          <label className="form-label required">Mục Tiêu Cho Phép Quét</label>
          <textarea
            className={`form-control ${errors.target ? 'is-invalid' : ''}`}
            rows="3"
            placeholder={
              formData.type === 'WEB'
                ? 'Nhập domain hoặc URL:\nhttps://sinhvien.attt.edu.vn\nhttp://192.168.1.50:8080'
                : 'Nhập IP hoặc dải mạng:\n192.168.10.55\n10.0.1.0/24\nscanme.nmap.org'
            }
            value={formData.target}
            onChange={(e) => setFormData({ ...formData, target: e.target.value })}
            disabled={isSubmitting}
            style={{ padding: '0.9rem 1.15rem', minHeight: '90px' }}
          ></textarea>
          {errors.target && <div className="form-error">{errors.target}</div>}
        </div>

        <div className="form-group" style={{ marginBottom: '1.75rem' }}>
          <label className="form-label">Mục Tiêu Loại Trừ</label>
          <textarea
            className="form-control"
            rows="2"
            placeholder="Các địa chỉ IP/URL cấm không được quét. Ví dụ: 192.168.10.1, 10.0.1.254"
            value={formData.excludedTarget}
            onChange={(e) => setFormData({ ...formData, excludedTarget: e.target.value })}
            disabled={isSubmitting}
            style={{ padding: '0.9rem 1.15rem', minHeight: '75px' }}
          ></textarea>
        </div>

        <div className="form-group" style={{ marginBottom: '2.25rem' }}>
          <label className="form-label">Ghi Chú Đợt Đánh Giá</label>
          <input
            type="text"
            className="form-control"
            placeholder="Ghi chú thêm về đợt đánh giá..."
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
            disabled={isSubmitting}
            style={{ padding: '0.9rem 1.15rem' }}
          />
        </div>

        <div style={{ display: 'flex', gap: '1rem', paddingTop: '1.25rem', borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <button type="submit" className="btn btn-primary" disabled={isSubmitting} style={{ minWidth: '220px', padding: '0.85rem 1.65rem', fontSize: '0.95rem' }}>
            <i className={`fa-solid ${isSubmitting ? 'fa-spinner fa-spin' : 'fa-shield-halved'}`}></i>
            {isSubmitting ? 'Đang Tạo...' : 'Khởi Tạo Đánh Giá Toàn Diện'}
          </button>
          <button type="button" className="btn btn-outline" onClick={onCancel} disabled={isSubmitting} style={{ padding: '0.85rem 1.65rem', fontSize: '0.95rem' }}>
            <i className="fa-solid fa-xmark"></i> Hủy Bỏ
          </button>
        </div>
      </form>
    </div>
  );
}
