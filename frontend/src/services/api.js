import axios from 'axios';

// 1. Hệ thống Event Bus phát thông báo Toast tập trung
export const toastEmitter = {
  listeners: [],
  subscribe(fn) {
    this.listeners.push(fn);
    return () => {
      this.listeners = this.listeners.filter((listener) => listener !== fn);
    };
  },
  show(title, message, type = 'info', duration = 4500) {
    this.listeners.forEach((fn) =>
      fn({ id: Date.now() + Math.random(), title, message, type, duration })
    );
  },
};

// 2. Quản lý Auth Token & Thông tin phiên đăng nhập
export const authStorage = {
  getToken: () => localStorage.getItem('access_token') || '',
  setToken: (token) => {
    localStorage.setItem('access_token', token);
    window.dispatchEvent(new Event('auth-change'));
  },
  removeToken: () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_info');
    window.dispatchEvent(new Event('auth-change'));
  },
  getUser: () => {
    const raw = localStorage.getItem('user_info');
    return raw ? JSON.parse(raw) : { name: 'Chuyên viên ATTT', role: 'ROLE_ADMIN', email: 'admin@attt.edu.vn' };
  },
};

// 3. Khởi tạo Axios Instance chính của hệ thống
export const apiClient = axios.create({
  baseURL: 'http://localhost:8080/api',
  timeout: 120000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// ==============================================================================
// 4. REQUEST INTERCEPTOR: Tự động đính kèm JWT Bearer Token
// ==============================================================================
apiClient.interceptors.request.use(
  (config) => {
    const token = authStorage.getToken();
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    toastEmitter.show('Lỗi khởi tạo yêu cầu', 'Không thể tạo request gửi tới máy chủ.', 'error');
    return Promise.reject(error);
  }
);

// ==============================================================================
// 5. RESPONSE INTERCEPTOR: Bắt lỗi API tập trung
// ==============================================================================
apiClient.interceptors.response.use(
  (response) => {
    return response.data;
  },
  (error) => {
    if (error.response) {
      const status = error.response.status;
      const data = error.response.data;
      let rawMsg = data?.message || data?.error || 'Đã xảy ra lỗi khi xử lý yêu cầu.';

      // Chuyển đổi các mã lỗi kỹ thuật phức tạp của Active Directory / Windows sang tiếng Việt thân thiện
      let message = rawMsg;
      if (typeof rawMsg === 'string') {
        if (rawMsg.includes('data 52e')) {
          message = 'Sai tên đăng nhập hoặc mật khẩu Active Directory (Lỗi Windows: data 52e). Vui lòng kiểm tra lại Username và Password.';
        } else if (rawMsg.includes('data 525')) {
          message = 'Tài khoản không tồn tại trên hệ thống Active Directory (Lỗi Windows: data 525).';
        } else if (rawMsg.includes('data 532')) {
          message = 'Mật khẩu tài khoản Active Directory đã hết hạn (Lỗi Windows: data 532).';
        } else if (rawMsg.includes('data 533')) {
          message = 'Tài khoản Active Directory đang bị vô hiệu hóa (Disabled - Lỗi Windows: data 533).';
        } else if (rawMsg.includes('data 775')) {
          message = 'Tài khoản Active Directory đã bị khóa do nhập sai mật khẩu nhiều lần (Lỗi Windows: data 775).';
        } else if (rawMsg.includes('Transport encryption required')) {
          message = 'Máy chủ Active Directory yêu cầu mã hóa kết nối. Hãy tích chọn "Sử dụng mã hóa LDAPS" cổng 636.';
        } else if (rawMsg.length > 200) {
          message = rawMsg.substring(0, 197) + '...';
        }
      }

      switch (status) {
        case 400:
          toastEmitter.show('400 - Xác thực không thành công', message, 'warning');
          break;

        case 401:
          toastEmitter.show('401 - Hết phiên đăng nhập', 'Phiên làm việc đã hết hạn. Vui lòng đăng nhập lại.', 'error');
          authStorage.removeToken();
          break;

        case 403:
          toastEmitter.show('403 - Từ chối truy cập', 'Bạn không có quyền hạn truy cập tài nguyên này.', 'error');
          break;

        case 404:
          // Không hiện toast phiền toái đối với các truy vấn GET kiểm tra dữ liệu chưa khởi tạo
          if (error.config?.method?.toLowerCase() !== 'get') {
            toastEmitter.show('404 - Không tìm thấy', message || 'Tài nguyên yêu cầu không tồn tại trên máy chủ.', 'warning');
          }
          break;

        case 422:
          toastEmitter.show('422 - Lỗi nghiệp vụ', message, 'warning');
          break;

        case 500:
          toastEmitter.show('500 - Lỗi máy chủ', message || 'Hệ thống máy chủ gặp sự cố nội bộ. Vui lòng thử lại sau.', 'error');
          break;

        case 502:
        case 503:
        case 504:
          toastEmitter.show(`${status} - Máy chủ không khả dụng`, 'Dịch vụ máy chủ tạm thời gián đoạn hoặc quá tải.', 'error');
          break;

        default:
          toastEmitter.show(`Lỗi ${status}`, message, 'error');
          break;
      }
    } else if (error.code === 'ECONNABORTED' || error.message?.toLowerCase().includes('timeout')) {
      toastEmitter.show(
        'Đang xử lý ngầm (Timeout)',
        'Tiến trình AI / Quét Nmap đang xử lý ngầm trên máy chủ. Kết quả sẽ hiển thị ngay khi hoàn tất.',
        'info',
        6000
      );
    } else if (error.request) {
      toastEmitter.show(
        'Mất kết nối máy chủ',
        'Không thể kết nối đến Backend (http://localhost:8080). Hãy đảm bảo ứng dụng Spring Boot đang chạy.',
        'error',
        6000
      );
    } else {
      toastEmitter.show('Lỗi hệ thống', error.message || 'Đã xảy ra lỗi không xác định.', 'error');
    }

    return Promise.reject(error);
  }
);

// Gán thêm ra window để linh hoạt
if (typeof window !== 'undefined') {
  window.apiClient = apiClient;
  window.toastEmitter = toastEmitter;
  window.authStorage = authStorage;
}

export default apiClient;
