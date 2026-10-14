# Môi Trường Kiểm Thử (Target Test Labs) - ATTT Portal

Thư mục này chứa cấu hình và tài nguyên phục vụ việc rà quét kiểm thử an toàn thông tin nội bộ (Local Penetration Testing & Reconnaissance Lab).

---

## 🚀 Cách khởi chạy các máy chủ mục tiêu với Docker

Tại thư mục gốc của dự án, chạy lệnh:

```bash
docker compose up -d
```

Docker Compose sẽ tự động khởi tạo:
1. **PostgreSQL Database** (`security-postgres`): Cổng `15432:5432`
2. **Apache HTTPD Web Server** (`security-target-apache`): Cổng `8088:80`
3. **Apache Tomcat Application Server** (`security-target-tomcat`): Cổng `8888:8080`, AJP `8009:8009`

---

## 🎯 Thông tin mục tiêu rà quét trên ATTT Portal

| Dịch vụ mục tiêu | URL / Host trên máy | Cổng mục tiêu | Chức năng kiểm thử |
| :--- | :--- | :--- | :--- |
| **Apache Web Server** | `http://localhost:8088` | `8088` (HTTP) | Rà quét Tech Stack (Apache 2.4), Nmap rà cổng, kiểm tra tệp tin nhạy cảm (`/backup.zip`, `/robots.txt`). |
| **Apache Tomcat** | `http://localhost:8888` | `8888` (HTTP), `8009` (AJP) | Rà quét Tech Stack Tomcat 9.0, quét lỗ hổng CVE Intelligence (Ghostcat, PUT RCE, Deserialization). |

*Lưu ý: Cổng Tomcat được ánh xạ ra `8888` trên máy Host để tránh xung đột với Spring Boot Backend (chạy mặc định cổng `8080`).*
