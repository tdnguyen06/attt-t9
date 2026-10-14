# Hệ Thống Quản Trị & Giám Sát An Toàn Thông Tin (ATTT Portal)

Kiến trúc kết hợp: **Spring Boot Backend (Port 8080)** + **React 18 (Vite + JSX) Frontend**.

---

## 📁 Cấu Trúc Dự Án Chuẩn React JSX (Người B)

```
ATTT---T9/
├── backend/
│   ├── pom.xml                                               # Quản lý Spring Boot
│   ├── mvnw / mvnw.cmd                                       # Maven Wrapper chạy trực tiếp
│   └── src/main/java/com/example/demo/
│       ├── DemoApplication.java                              # Spring Boot Main
│       └── resources/application.properties                  # Cấu hình port 8080
└── frontend/                                                 # React 18 + Vite (Chuẩn JSX Modular)
    ├── package.json                                          # Quản lý thư viện (React, Axios, Vite)
    ├── vite.config.js                                        # Cấu hình Vite & Proxy tới Spring Boot 8080
    ├── index.html                                            # Entry point HTML của SPA
    └── src/
        ├── main.jsx                                          # Khởi chạy React DOM Root
        ├── App.jsx                                           # Layout tổng hợp (Sidebar + Header + Content Area)
        ├── index.css                                         # Giao diện Dark-Slate ATTT Dashboard
        ├── services/
        │   └── api.js                                        # [Người B] Axios Interceptor bắt lỗi & gắn JWT Token
        ├── components/
        │   ├── Header.jsx                                    # [Người B] Component Header (.jsx)
        │   ├── Sidebar.jsx                                   # [Người B] Component Sidebar (.jsx)
        │   └── ToastNotification.jsx                         # [Người B] Toast thông báo lỗi tập trung (.jsx)
        └── views/
            ├── DashboardView.jsx                             # Trang Bảng điều khiển giám sát (.jsx)
            ├── UsersView.jsx                                 # Trang Quản lý người dùng & RBAC (.jsx)
            ├── AuditLogsView.jsx                             # Trang Nhật ký kiểm toán & bảo mật (.jsx)
            └── SecurityConfigView.jsx                        # Trang Cấu hình chính sách an toàn (.jsx)
```

---

## 🎯 Chi Tiết Nhiệm Vụ Người B Đã Triển Khai

### 1. Kiến Trúc Layout React (.jsx):
- **`Sidebar.jsx`**:
  - Menu điều hướng phân nhóm: *Giám Sát, Quản Trị, Hệ Thống*.
  - Hỗ trợ thu gọn/mở rộng (Collapse/Expand) với hiệu ứng animation mượt mà.
  - Thẻ thông tin tài khoản chuyên viên ở chân Sidebar.
- **`Header.jsx`**:
  - Tích hợp Breadcrumbs động theo từng View.
  - Nút toggle Sidebar, trạng thái hoạt động của Interceptor, chuông thông báo.
- **`ToastNotification.jsx`**:
  - Bắt các sự kiện thông báo lỗi / thành công từ Interceptor để hiển thị popup góc trên bên phải màn hình.
- **`Content Area (views/)`**:
  - Vùng hiển thị động các trang nghiệp vụ (`DashboardView.jsx`, `UsersView.jsx`, `AuditLogsView.jsx`, `SecurityConfigView.jsx`).

### 2. Axios Interceptor Bắt Lỗi Tập Trung (`src/services/api.js`):
- **Request Interceptor**: Tự động trích xuất JWT Token từ `localStorage` và đính kèm `Authorization: Bearer <token>` vào header.
- **Response Interceptor**: Xử lý mã lỗi HTTP tự động và kích hoạt Toast Notification:
  - `401 Unauthorized`: Tự động xóa Token khỏi bộ nhớ, thông báo phiên hết hạn.
  - `403 Forbidden`: Báo lỗi từ chối truy cập do thiếu quyền.
  - `404 Not Found`: Báo lỗi tài nguyên không tồn tại.
  - `500 Server Error`: Báo lỗi nội bộ từ máy chủ Backend.
  - `Network Error`: Báo mất kết nối tới Backend Spring Boot.

---

## 💻 Hướng Dẫn Dành Cho Đồng Đội (Người A & Người C)

Import và gọi API bất kỳ thông qua `apiClient`:
```javascript
import apiClient from '../services/api';

async function fetchUsers() {
  try {
    const data = await apiClient.get('/users');
    console.log('Danh sách users:', data);
  } catch (error) {
    // Interceptor đã tự động bắt lỗi và hiển thị Toast lên màn hình!
  }
}
```

---

## 🚀 Cách Chạy Ứng Dụng

### 1. Khởi Chạy Cơ Sở Dữ Liệu & Các Mục Tiêu Kiểm Thử (Docker Compose):
```powershell
docker compose up -d
```
Lệnh này sẽ tự động khởi động:
- **PostgreSQL 17** (`security-postgres`): Cổng `15432:5432`
- **Apache Web Server Test Target** (`security-target-apache`): Cổng `8088:80` (Mục tiêu rà quét HTTP, Header, Tech Stack, `/backup.zip`)
- **Apache Tomcat Test Target** (`security-target-tomcat`): Cổng `8888:8080`, AJP `8009` (Mục tiêu rà quét Tomcat CVEs, Ghostcat, Java Web)

### 2. Backend (Spring Boot):
```powershell
cd backend
.\mvnw.cmd spring-boot:run
```
Backend chạy tại: `http://localhost:8080`.

### 3. Frontend (React + Vite):
```powershell
cd frontend
npm install
npm run dev
```
Trình duyệt sẽ mở tại: `http://localhost:3000` (hoặc `http://localhost:5173`).

