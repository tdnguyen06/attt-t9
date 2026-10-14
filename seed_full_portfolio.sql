-- ==============================================================================
-- SEED FULL PORTFOLIO OF ASSESSMENTS, SCOPES, SCANS, PLANS & REPORTS
-- Targets: Diverse Web URLs & Network IPs
-- ==============================================================================

BEGIN;

-- 1. ASSESSMENTS
INSERT INTO assessments (id, name, type, status, created_by, description, created_at, updated_at) VALUES
(2, 'Kiểm thử ứng dụng Web Portal & Cổng xác thực SSO', 'WEB', 'COMPLETED', 'Chuyên viên ATTT', 
 'Đánh giá an ninh ứng dụng Web Portal trung tâm, rà soát cơ chế xác thực SSO OAuth2/OIDC, kiểm thử phương thức HTTP và cấu hình bảo mật tiêu chuẩn OWASP.', 
 NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days' + INTERVAL '25 minutes'),

(3, 'Rà quét hạ tầng mạng DMZ & Gateway mạng nội bộ', 'SERVER', 'COMPLETED', 'Chuyên viên ATTT', 
 'Rà soát an ninh hạ tầng mạng phân vùng DMZ, cổng thiết bị định tuyến Gateway và các máy chủ trung gian chuyển mạch.', 
 NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days' + INTERVAL '18 minutes'),

(4, 'Đánh giá an toàn Cổng thanh toán & Dịch vụ trực tuyến', 'WEB', 'COMPLETED', 'Chuyên viên ATTT', 
 'Kiểm thử an toàn cổng giao dịch trực tuyến, rà quét bề mặt tấn công Web server Apache/Tomcat, rà quét lộ lọt mã nguồn và cấu hình SSL/TLS.', 
 NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days' + INTERVAL '30 minutes'),

(5, 'Kiểm tra bảo mật máy chủ Cơ sở dữ liệu & Caching nội bộ', 'SERVER', 'COMPLETED', 'Chuyên viên ATTT', 
 'Rà quét cổng dịch vụ lưu trữ dữ liệu PostgreSQL, MySQL và máy chủ Redis cache; đánh giá rủi ro xác thực mật khẩu mặc định và rò rỉ cổng ra ngoài mạng.', 
 NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days' + INTERVAL '15 minutes'),

(6, 'Kiểm tra an ninh REST API Gateway & Microservices', 'WEB', 'COMPLETED', 'Chuyên viên ATTT', 
 'Đánh giá bảo mật toàn diện chuỗi API Gateway Spring Boot / Express, kiểm tra endpoint nhạy cảm Actuator, Swagger docs và cơ chế ký JWT.', 
 NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day' + INTERVAL '22 minutes'),

(7, 'Rà soát an ninh máy chủ Quản lý mã nguồn & CI/CD', 'SERVER', 'COMPLETED', 'Chuyên viên ATTT', 
 'Kiểm tra cấu hình máy chủ GitLab nội bộ, Docker Registry và các runner thực thi tự động nhằm ngăn chặn nguy cơ tấn công chuỗi cung ứng.', 
 NOW() - INTERVAL '18 hours', NOW() - INTERVAL '18 hours' + INTERVAL '12 minutes'),

(8, 'Đánh giá an toàn Cổng tra cứu văn bản & Tài liệu nội bộ', 'WEB', 'COMPLETED', 'Chuyên viên ATTT', 
 'Rà soát an ninh hệ thống quản lý tài liệu và cổng đào tạo nội bộ, kiểm tra quyền truy cập tệp tin và chính sách bảo vệ nội dung CSP.', 
 NOW() - INTERVAL '12 hours', NOW() - INTERVAL '12 hours' + INTERVAL '14 minutes'),

(9, 'Rà quét an ninh cụm máy chủ Giám sát SIEM & Log tập trung', 'SERVER', 'COMPLETED', 'Chuyên viên ATTT', 
 'Đánh giá an toàn cụm lưu trữ log Elasticsearch, giao diện Kibana và Logstash; phòng chống rò rỉ dữ liệu nhật ký hệ thống nhạy cảm.', 
 NOW() - INTERVAL '8 hours', NOW() - INTERVAL '8 hours' + INTERVAL '20 minutes'),

(10, 'Kiểm tra an ninh Cổng truy cập từ xa VPN SSL & Gateway', 'SERVER', 'COMPLETED', 'Chuyên viên ATTT', 
 'Kiểm thử bảo mật máy chủ OpenVPN Access Server và Gateway kết nối từ xa; rà soát phiên bản mã hóa TLS và cơ chế xác thực đa yếu tố 2FA.', 
 NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours' + INTERVAL '10 minutes')
ON CONFLICT (id) DO UPDATE SET 
    name = EXCLUDED.name,
    type = EXCLUDED.type,
    status = EXCLUDED.status,
    description = EXCLUDED.description;

-- 2. SCOPES (Targets)
INSERT INTO scopes (id, assessment_id, target, target_type, is_excluded, description, created_at) VALUES
(10, 2, 'https://portal.vncert.vn', 'URL', false, 'Cổng thông tin điện tử trung tâm của tổ chức', NOW() - INTERVAL '5 days'),
(11, 2, 'https://sso.vncert.vn', 'URL', false, 'Máy chủ định danh & xác thực tập trung SSO', NOW() - INTERVAL '5 days'),
(12, 2, 'https://admin-secret.vncert.vn', 'URL', true, 'Phân vùng quản trị đặc quyền (loại trừ khỏi kiểm thử)', NOW() - INTERVAL '5 days'),

(20, 3, '192.168.54.1', 'IP', false, 'Thiết bị định tuyến Gateway chính phân vùng DMZ', NOW() - INTERVAL '4 days'),
(21, 3, '192.168.54.0/24', 'CIDR', false, 'Dải mạng nội bộ phân vùng DMZ', NOW() - INTERVAL '4 days'),
(22, 3, '192.168.54.254', 'IP', true, 'Tường lửa phần cứng Firewall (loại trừ)', NOW() - INTERVAL '4 days'),

(30, 4, 'https://shop.vncert.vn', 'URL', false, 'Cổng dịch vụ trực tuyến & thương mại điện tử', NOW() - INTERVAL '3 days'),
(31, 4, 'http://192.168.54.129:8080', 'URL', false, 'Cổng kiểm thử web ứng dụng Tomcat nội bộ', NOW() - INTERVAL '3 days'),

(40, 5, '192.168.54.130', 'IP', false, 'Máy chủ cơ sở dữ liệu PostgreSQL & Redis Cache chính', NOW() - INTERVAL '2 days'),
(41, 5, '192.168.54.131', 'IP', false, 'Máy chủ sao lưu dữ liệu Database Replica', NOW() - INTERVAL '2 days'),

(50, 6, 'https://api.vncert.vn', 'URL', false, 'REST API Gateway phục vụ các ứng dụng di động & Web', NOW() - INTERVAL '1 day'),
(51, 6, 'https://api-v2.vncert.vn', 'URL', false, 'Cụm API Microservices thử nghiệm phiên bản mới', NOW() - INTERVAL '1 day'),

(60, 7, '192.168.54.135', 'IP', false, 'Máy chủ quản lý mã nguồn GitLab nội bộ & Docker Registry', NOW() - INTERVAL '18 hours'),
(61, 7, 'https://gitlab.vncert.vn', 'URL', false, 'Tên miền truy cập Web UI của GitLab', NOW() - INTERVAL '18 hours'),

(70, 8, 'https://docs.vncert.vn', 'URL', false, 'Cổng tra cứu tài liệu nghiệp vụ nội bộ', NOW() - INTERVAL '12 hours'),
(71, 8, 'https://edu.vncert.vn', 'URL', false, 'Hệ thống đào tạo an toàn thông tin E-Learning', NOW() - INTERVAL '12 hours'),

(80, 9, '192.168.54.140', 'IP', false, 'Máy chủ lưu trữ và phân tích sự kiện an ninh SIEM', NOW() - INTERVAL '8 hours'),
(81, 9, 'http://192.168.54.140:9200', 'URL', false, 'Cổng dịch vụ Elasticsearch Cluster API', NOW() - INTERVAL '8 hours'),

(90, 10, 'https://vpn.vncert.vn', 'URL', false, 'Cổng VPN SSL truy cập mạng an toàn từ xa', NOW() - INTERVAL '3 hours'),
(91, 10, '192.168.54.254', 'IP', false, 'Giao diện nội bộ của thiết bị kết nối VPN', NOW() - INTERVAL '3 hours')
ON CONFLICT (id) DO UPDATE SET 
    target = EXCLUDED.target,
    target_type = EXCLUDED.target_type,
    is_excluded = EXCLUDED.is_excluded,
    description = EXCLUDED.description;

-- 3. ASSESSMENT PLANS
INSERT INTO assessment_plans (id, assessment_id, title, summary, risk_assessment, status, created_at, updated_at) VALUES
(2, 2, 'Kế hoạch kiểm thử an toàn Web Portal & SSO Gateway', 
 'Rà quét toàn diện cổng thông tin portal.vncert.vn và máy chủ sso.vncert.vn: kiểm tra phương thức HTTP, quét chứng chỉ SSL/TLS, nhận diện công nghệ web và kiểm tra các lỗ hổng xác thực phổ biến.', 
 'Rủi ro mức Cao do chứa dữ liệu danh tính người dùng toàn hệ thống.', 'COMPLETED', NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days'),

(3, 3, 'Kế hoạch rà soát hạ tầng thiết bị mạng DMZ', 
 'Thực hiện quét cổng TCP toàn diện trên Gateway 192.168.54.1 và dải mạng 192.168.54.0/24 để phát hiện các dịch vụ không cần thiết đang mở.', 
 'Rủi ro Trung bình đối với hạ tầng biên.', 'COMPLETED', NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days'),

(4, 4, 'Kế hoạch kiểm thử cổng dịch vụ trực tuyến & thanh toán', 
 'Rà quét bề mặt tấn công cổng shop.vncert.vn và dịch vụ Tomcat 8080: kiểm tra lỗ hổng lộ thư mục, kiểm tra mã độc web shell và cấu hình cipher TLS.', 
 'Rủi ro Cao do tiếp nhận giao dịch trực tiếp.', 'COMPLETED', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days'),

(5, 5, 'Kế hoạch kiểm thử máy chủ Database & Cache Redis', 
 'Kiểm tra dịch vụ PostgreSQL 5432 và Redis 6379 trên 192.168.54.130; rà soát cấu hình pg_hba.conf và xác thực Redis bind 0.0.0.0.', 
 'Rủi ro Nghiêm trọng do lưu trữ toàn bộ cơ sở dữ liệu nhạy cảm.', 'COMPLETED', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days'),

(6, 6, 'Kế hoạch đánh giá an toàn REST API Gateway', 
 'Kiểm thử bảo mật các endpoint API /actuator, /swagger-ui, kiểm tra phân quyền truy cập Token JWT và khả năng chống brute-force.', 
 'Rủi ro Nghiêm trọng: Nguy cơ lộ thông tin cấu hình môi trường.', 'COMPLETED', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day'),

(7, 7, 'Kế hoạch rà soát an ninh GitLab & CI/CD Runner', 
 'Kiểm thử máy chủ mã nguồn 192.168.54.135, rà soát cổng Docker daemon 2375/5005 và bảo mật SSH.', 
 'Rủi ro Trung bình.', 'COMPLETED', NOW() - INTERVAL '18 hours', NOW() - INTERVAL '18 hours'),

(8, 8, 'Kế hoạch kiểm thử cổng tài liệu nội bộ & E-Learning', 
 'Kiểm tra cấu hình bảo mật tiêu đề HTTP Security Headers (CSP, HSTS, X-Frame-Options) trên docs.vncert.vn và edu.vncert.vn.', 
 'Rủi ro Thấp.', 'COMPLETED', NOW() - INTERVAL '12 hours', NOW() - INTERVAL '12 hours'),

(9, 9, 'Kế hoạch rà soát an ninh cụm giám sát SIEM', 
 'Kiểm tra cổng 9200 Elasticsearch và cổng 5601 Kibana xem có yêu cầu xác thực người dùng hay không.', 
 'Rủi ro Cao: Có thể đọc trộm log hệ thống nếu thiếu xác thực.', 'COMPLETED', NOW() - INTERVAL '8 hours', NOW() - INTERVAL '8 hours'),

(10, 10, 'Kế hoạch đánh giá an ninh Gateway VPN SSL', 
 'Rà quét giao thức kết nối OpenVPN, thuật toán mã hóa AES-GCM và cấu hình bảo vệ chứng chỉ số CA.', 
 'Rủi ro Trung bình.', 'COMPLETED', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours')
ON CONFLICT (id) DO UPDATE SET 
    title = EXCLUDED.title,
    summary = EXCLUDED.summary,
    status = EXCLUDED.status;

-- 4. SCAN TASKS
INSERT INTO scan_tasks (id, assessment_id, target, profile, command_line, status, parsed_summary, ai_explanation, exit_code, duration_ms, created_at, started_at, completed_at) VALUES
(10, 2, 'https://portal.vncert.vn', 'FULL_COMPREHENSIVE_SCAN', 'nmap -sT -p 80,443 -sV portal.vncert.vn', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":2,"openPorts":[{"port":80,"protocol":"tcp","service":"http","state":"open","version":"nginx/1.22.1"},{"port":443,"protocol":"tcp","service":"https","state":"open","version":"nginx/1.22.1 (SSL)"}],"recon":{"httpSecurity":{"score":70,"grade":"B","serverHeader":"nginx/1.22.1","hsts":true,"csp":false,"xFrameOptions":true},"techStack":{"detected":[{"category":"Web Server","name":"Nginx 1.22.1"},{"category":"Frontend Framework","name":"React 18.2"},{"category":"Backend","name":"Node.js Express"}]},"webDirectories":{"discoveredPaths":["/api/v1","/login","/dashboard","/assets","/static"]}}}',
'{"summary":"Mục tiêu https://portal.vncert.vn đang vận hành Nginx 1.22.1 trên cổng 80 và 443. Hệ thống đã kích hoạt HSTS và X-Frame-Options, tuy nhiên thiếu tiêu đề Content-Security-Policy (CSP) dẫn đến nguy cơ XSS.","riskLevel":"MEDIUM","portsExplanation":[{"port":80,"service":"HTTP (Redirect to HTTPS)","explanation":"Chuyển hướng an toàn sang HTTPS 443"},{"port":443,"service":"HTTPS","explanation":"Cung cấp giao diện Web Portal chính thức"}],"securityRisks":["Thiếu Content-Security-Policy (CSP)","Lộ phiên bản chi tiết Nginx trong Server Header"],"stepByStepGuide":["Bổ sung tiêu đề CSP trong file cấu hình nginx.conf: add_header Content-Security-Policy \"default-src ''self'';\";","Bật chỉ thị server_tokens off; trong Nginx để ẩn số hiệu phiên bản."]}',
0, 2450, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days' + INTERVAL '3 seconds'),

(11, 2, 'https://sso.vncert.vn', 'QUICK_SCAN', 'nmap -sT -F sso.vncert.vn', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":1,"openPorts":[{"port":443,"protocol":"tcp","service":"https","state":"open","version":"OpenResty / Keycloak 22"}],"recon":{"httpSecurity":{"score":85,"grade":"A","serverHeader":"Keycloak-SSO","hsts":true,"csp":true,"xFrameOptions":true},"techStack":{"detected":[{"category":"IAM / SSO","name":"Keycloak 22.0"},{"category":"Runtime","name":"Java OpenJDK 17"}]}}}',
'{"summary":"Máy chủ xác thực SSO https://sso.vncert.vn hoạt động bảo mật cao trên cổng HTTPS 443, đạt điểm bảo mật hạng A với đầy đủ HSTS, CSP và X-Frame-Options.","riskLevel":"LOW","portsExplanation":[{"port":443,"service":"HTTPS SSO","explanation":"Dịch vụ đăng nhập một lần Keycloak IAM"}],"securityRisks":["Cần theo dõi các bản vá lỗi CVE cho Keycloak định kỳ"],"stepByStepGuide":["Duy trì cập nhật phiên bản Keycloak mới nhất","Cấu hình giám sát số lượng yêu cầu xác thực bất thường (Rate limiting)"]}',
0, 1820, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days' + INTERVAL '2 seconds'),

(20, 3, '192.168.54.1', 'TOP_100_PORTS', 'nmap -sT --top-ports 100 192.168.54.1', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":4,"openPorts":[{"port":22,"protocol":"tcp","service":"ssh","state":"open","version":"Dropbear SSH 2022.82"},{"port":53,"protocol":"tcp","service":"domain","state":"open","version":"dnsmasq 2.86"},{"port":80,"protocol":"tcp","service":"http","state":"open","version":"LuCI OpenWrt"},{"port":443,"protocol":"tcp","service":"https","state":"open","version":"uHTTPd"}]}',
'{"summary":"Gateway DMZ 192.168.54.1 mở 4 cổng dịch vụ quản trị: SSH 22, DNS 53, HTTP 80 và HTTPS 443. Giao diện quản trị LuCI đang cho phép kết nối qua HTTP không mã hóa.","riskLevel":"MEDIUM","portsExplanation":[{"port":22,"service":"SSH (Dropbear)","explanation":"Giao diện dòng lệnh cấu hình thiết bị"},{"port":53,"service":"DNS (dnsmasq)","explanation":"Dịch vụ phân giải tên miền nội bộ"},{"port":80,"service":"HTTP LuCI","explanation":"Trang đăng nhập quản trị không mã hóa"},{"port":443,"service":"HTTPS LuCI","explanation":"Trang quản trị có chứng chỉ số"}],"securityRisks":["Giao diện quản trị cho phép truy cập qua HTTP cổng 80","Dropbear SSH có thể bị tấn công brute-force nếu không giới hạn IP"],"stepByStepGuide":["Chuyển hướng toàn bộ cổng 80 sang cổng 443 trên uHTTPd","Giới hạn truy cập cổng 22 chỉ từ dải IP quản trị viên"]}',
0, 3100, NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days' + INTERVAL '3 seconds'),

(30, 4, 'https://shop.vncert.vn', 'FULL_COMPREHENSIVE_SCAN', 'nmap -sT -p 80,443,8080 -sV shop.vncert.vn', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":3,"openPorts":[{"port":80,"protocol":"tcp","service":"http","state":"open","version":"Apache 2.4.52"},{"port":443,"protocol":"tcp","service":"https","state":"open","version":"Apache 2.4.52 (OpenSSL 1.1.1)"},{"port":8080,"protocol":"tcp","service":"http-proxy","state":"open","version":"Apache Tomcat 9.0.58"}],"recon":{"httpSecurity":{"score":55,"grade":"C","serverHeader":"Apache/2.4.52 (Ubuntu)","hsts":false,"csp":false},"techStack":{"detected":[{"category":"Web Server","name":"Apache 2.4.52"},{"category":"Application Server","name":"Tomcat 9.0.58"},{"category":"Language","name":"PHP 8.1"}]},"webDirectories":{"discoveredPaths":["/shop","/checkout","/admin-backup.zip","/api/order"]}}}',
'{"summary":"Cổng dịch vụ trực tuyến https://shop.vncert.vn phát hiện lỗ hổng nghiêm trọng: tệp tin sao lưu /admin-backup.zip công khai trên máy chủ Web, kèm theo thiếu vắng chính sách HSTS và CSP.","riskLevel":"HIGH","portsExplanation":[{"port":80,"service":"HTTP","explanation":"Cổng HTTP mở chưa ép buộc mã hóa HTTPS"},{"port":443,"service":"HTTPS","explanation":"Cổng giao dịch mua sắm chính"},{"port":8080,"service":"Tomcat 9","explanation":"Cổng backend API thanh toán"}],"securityRisks":["Lộ tệp sao lưu /admin-backup.zip chứa mã nguồn","Chưa kích hoạt HSTS (HTTP Strict Transport Security)","Tomcat 9.0.58 có lỗ hổng CVE cần cập nhật"],"stepByStepGuide":["Xóa ngay tệp admin-backup.zip khỏi thư mục web root /var/www/html","Cấu hình chặn truy cập trực tiếp vào cổng 8080 từ Internet, chỉ cho phép proxy qua Apache","Bật HSTS trong Apache: Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\""]}',
0, 4200, NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days' + INTERVAL '4 seconds'),

(40, 5, '192.168.54.130', 'FULL_PORT_SCAN', 'nmap -sT -p 22,5432,6379,3306 192.168.54.130', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":3,"openPorts":[{"port":22,"protocol":"tcp","service":"ssh","state":"open","version":"OpenSSH 8.9p1 Ubuntu"},{"port":5432,"protocol":"tcp","service":"postgresql","state":"open","version":"PostgreSQL 15.4"},{"port":6379,"protocol":"tcp","service":"redis","state":"open","version":"Redis 7.0.12 (UNAUTHENTICATED)"}]}',
'{"summary":"CỰC KỲ NGUY HIỂM: Máy chủ cơ sở dữ liệu 192.168.54.130 đang mở cổng Redis 6379 KHÔNG YÊU CẦU MẬT KHẨU (No Auth)! Bất kỳ kẻ tấn công nào cũng có thể kết nối đọc ghi dữ liệu hoặc ghi SSH key để chiếm quyền root.","riskLevel":"CRITICAL","portsExplanation":[{"port":22,"service":"SSH","explanation":"Dịch vụ truy cập máy chủ"},{"port":5432,"service":"PostgreSQL 15","explanation":"Hệ quản trị CSDL quan hệ chính"},{"port":6379,"service":"Redis Cache","explanation":"Bộ nhớ đệm Redis không có mật khẩu bảo vệ!"}],"securityRisks":["Redis mở công khai không yêu cầu mật khẩu xác thực (Unauthenticated Access)","PostgreSQL lắng nghe trên 0.0.0.0 thay vì 127.0.0.1"],"stepByStepGuide":["Cấu hình requirepass <mat_khau_manh> trong file redis.conf ngay lập tức","Đổi bind 127.0.0.1 trong redis.conf để chặn truy cập từ mạng ngoài","Thiết lập firewall UFW chỉ cho phép máy chủ Backend kết nối tới cổng 5432"]}',
0, 2150, NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days' + INTERVAL '2 seconds'),

(50, 6, 'https://api.vncert.vn', 'FULL_COMPREHENSIVE_SCAN', 'nmap -sT -p 443,8443 -sV api.vncert.vn', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":2,"openPorts":[{"port":443,"protocol":"tcp","service":"https","state":"open","version":"Spring Boot Gateway"},{"port":8443,"protocol":"tcp","service":"https-alt","state":"open","version":"Actuator Management Port"}],"recon":{"httpSecurity":{"score":60,"grade":"B","serverHeader":"Spring-WebFlux","hsts":true},"techStack":{"detected":[{"category":"Framework","name":"Spring Boot 3.2.0"},{"category":"Runtime","name":"Java OpenJDK 21"},{"category":"API Gateway","name":"Spring Cloud Gateway"}]},"webDirectories":{"discoveredPaths":["/actuator","/actuator/env","/actuator/health","/swagger-ui.html","/api/v1/auth"]}}}',
'{"summary":"Phát hiện endpoint giám sát Spring Boot Actuator (/actuator/env) bị lộ lọt không có xác thực trên API Gateway https://api.vncert.vn. Kẻ tấn công có thể đọc biến môi trường chứa mật khẩu DB và API Key.","riskLevel":"CRITICAL","portsExplanation":[{"port":443,"service":"HTTPS API Gateway","explanation":"Cổng tiếp nhận request người dùng"},{"port":8443,"service":"Actuator Management","explanation":"Cổng giám sát nội bộ để lộ ra ngoài"}],"securityRisks":["Lộ lọt thông tin biến môi trường qua /actuator/env","Tài liệu API Swagger công khai không bảo vệ"],"stepByStepGuide":["Vô hiệu hóa endpoint env: management.endpoints.web.exposure.exclude=env trong application.properties","Bảo vệ các endpoint actuator bằng Spring Security với quyền ADMIN","Ẩn tài liệu Swagger trên môi trường Production"]}',
0, 3600, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day' + INTERVAL '4 seconds'),

(60, 7, '192.168.54.135', 'TOP_100_PORTS', 'nmap -sT -p 22,80,443,5005 192.168.54.135', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":4,"openPorts":[{"port":22,"protocol":"tcp","service":"ssh","state":"open","version":"OpenSSH 8.4p1 Debian"},{"port":80,"protocol":"tcp","service":"http","state":"open","version":"nginx (GitLab CE)"},{"port":443,"protocol":"tcp","service":"https","state":"open","version":"nginx (GitLab CE)"},{"port":5005,"protocol":"tcp","service":"docker-registry","state":"open","version":"Docker Registry v2"}]}',
'{"summary":"Máy chủ GitLab nội bộ 192.168.54.135 đang vận hành Docker Container Registry trên cổng 5005. Dịch vụ web hoạt động ổn định trên HTTPS.","riskLevel":"MEDIUM","portsExplanation":[{"port":22,"service":"Git over SSH","explanation":"Thao tác git clone / push"},{"port":80,"service":"HTTP","explanation":"Tự động chuyển tiếp 443"},{"port":443,"service":"HTTPS GitLab Web","explanation":"Giao diện quản lý mã nguồn"},{"port":5005,"service":"Docker Registry","explanation":"Lưu trữ image phục vụ CI/CD"}],"securityRisks":["Cổng 5005 Docker Registry cần đảm bảo có xác thực Token","Kiểm tra phiên bản GitLab phòng chống lỗ hổng RCE CVE-2023-7028"],"stepByStepGuide":["Đảm bảo tính năng 2FA bắt buộc cho tài khoản lập trình viên","Thường xuyên cập nhật GitLab lên bản vá an ninh mới nhất"]}',
0, 2800, NOW() - INTERVAL '18 hours', NOW() - INTERVAL '18 hours', NOW() - INTERVAL '18 hours' + INTERVAL '3 seconds'),

(70, 8, 'https://docs.vncert.vn', 'QUICK_SCAN', 'nmap -sT -p 80,443 docs.vncert.vn', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":2,"openPorts":[{"port":80,"protocol":"tcp","service":"http","state":"open","version":"Caddy v2.7"},{"port":443,"protocol":"tcp","service":"https","state":"open","version":"Caddy v2.7 (Auto TLS)"}],"recon":{"httpSecurity":{"score":90,"grade":"A","serverHeader":"Caddy","hsts":true,"csp":true,"xFrameOptions":true},"techStack":{"detected":[{"category":"Static Site","name":"Docusaurus 3.0"},{"category":"Web Server","name":"Caddy 2"}]}}}',
'{"summary":"Cổng tài liệu docs.vncert.vn sử dụng Caddy Web Server với khả năng tự động cấp chứng chỉ TLS Let''s Encrypt, đạt điểm bảo mật xuất sắc hạng A.","riskLevel":"LOW","portsExplanation":[{"port":80,"service":"HTTP","explanation":"Tự động chuyển tiếp 443"},{"port":443,"service":"HTTPS","explanation":"Máy chủ tài liệu mã hóa chuẩn TLS 1.3"}],"securityRisks":["Không phát hiện rủi ro bảo mật đáng kể"],"stepByStepGuide":["Duy trì cấu hình hiện tại","Thường xuyên sao lưu dữ liệu tài liệu tĩnh"]}',
0, 1600, NOW() - INTERVAL '12 hours', NOW() - INTERVAL '12 hours', NOW() - INTERVAL '12 hours' + INTERVAL '2 seconds'),

(80, 9, '192.168.54.140', 'SERVICE_VERSION', 'nmap -sT -p 22,5601,9200,5044 -sV 192.168.54.140', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":4,"openPorts":[{"port":22,"protocol":"tcp","service":"ssh","state":"open","version":"OpenSSH 9.0"},{"port":5044,"protocol":"tcp","service":"lumberjack","state":"open","version":"Logstash Beats"},{"port":5601,"protocol":"tcp","service":"kibana","state":"open","version":"Kibana 8.11.0"},{"port":9200,"protocol":"tcp","service":"wap-wsp","state":"open","version":"Elasticsearch REST API 8.11.0"}]}',
'{"summary":"Máy chủ SIEM 192.168.54.140 mở các cổng phân tích log: Elasticsearch 9200 và Kibana 5601. Dữ liệu giám sát an ninh yêu cầu bảo vệ nghiêm ngặt tránh việc xóa log làm mất dấu vết tấn công.","riskLevel":"HIGH","portsExplanation":[{"port":22,"service":"SSH","explanation":"Quản trị máy chủ Linux"},{"port":5044,"service":"Logstash","explanation":"Cổng thu thập sự kiện log từ máy trạm"},{"port":5601,"service":"Kibana Dashboard","explanation":"Giao diện trực quan hóa dữ liệu"},{"port":9200,"service":"Elasticsearch","explanation":"Công cụ tìm kiếm và lưu trữ chỉ mục log"}],"securityRisks":["Cần đảm bảo cổng 9200 Elasticsearch bắt buộc xác thực TLS và Basic Auth","Kibana cần kích hoạt session cookie an toàn (Secure, HttpOnly)"],"stepByStepGuide":["Cấu hình xpack.security.enabled: true trong elasticsearch.yml","Giới hạn chỉ cho phép các IP máy chủ thu thập log gửi dữ liệu đến cổng 5044"]}',
0, 3400, NOW() - INTERVAL '8 hours', NOW() - INTERVAL '8 hours', NOW() - INTERVAL '8 hours' + INTERVAL '3 seconds'),

(90, 10, 'https://vpn.vncert.vn', 'FULL_COMPREHENSIVE_SCAN', 'nmap -sT -p 443,943,1194 -sV vpn.vncert.vn', 'COMPLETED',
'{"totalHostsUp":1,"totalOpenPorts":3,"openPorts":[{"port":443,"protocol":"tcp","service":"https","state":"open","version":"OpenVPN Web Portal"},{"port":943,"protocol":"tcp","service":"https-alt","state":"open","version":"OpenVPN Admin UI"},{"port":1194,"protocol":"tcp","service":"openvpn","state":"open","version":"OpenVPN Tunnel Protocol"}],"recon":{"httpSecurity":{"score":80,"grade":"B","serverHeader":"OpenVPN-Server","hsts":true}}}',
'{"summary":"Gateway VPN https://vpn.vncert.vn đang mở cổng 443 cho người dùng kết nối và cổng 943 cho trang quản trị. Khuyến nghị không để lộ trang quản trị cổng 943 ra Internet công cộng.","riskLevel":"MEDIUM","portsExplanation":[{"port":443,"service":"OpenVPN Web","explanation":"Tải client và cấu hình VPN"},{"port":943,"service":"OpenVPN Admin","explanation":"Trang đăng nhập quản trị VPN"},{"port":1194,"service":"OpenVPN Tunnel","explanation":"Đường hầm mã hóa dữ liệu mạng"}],"securityRisks":["Trang quản trị Admin cổng 943 đang mở ra ngoài Internet","Cần kiểm tra chính sách xác thực đa yếu tố OTP/2FA"],"stepByStepGuide":["Khóa cổng 943 trên Firewall công cộng, chỉ cho phép quản trị qua mạng nội bộ","Kích hoạt xác thực 2FA Google Authenticator cho toàn bộ tài khoản VPN"]}',
0, 2750, NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours' + INTERVAL '3 seconds')
ON CONFLICT (id) DO UPDATE SET 
    target = EXCLUDED.target,
    profile = EXCLUDED.profile,
    command_line = EXCLUDED.command_line,
    status = EXCLUDED.status,
    parsed_summary = EXCLUDED.parsed_summary,
    ai_explanation = EXCLUDED.ai_explanation;

-- 5. PLAN STEPS
INSERT INTO plan_steps (id, plan_id, step_number, name, tool, profile, target, impact_level, requires_approval, is_approved, status, description, expected_outcome, result_summary, scan_task_id, created_at, approved_at, approved_by) VALUES
(20, 2, 1, 'Rà quét toàn diện Web Portal', 'nmap', 'FULL_COMPREHENSIVE_SCAN', 'https://portal.vncert.vn', 'LOW', false, true, 'SUCCESS', 'Dò quét cổng web, kiểm tra tiêu đề an toàn HTTP và nhận diện công nghệ', 'Phát hiện cổng 80, 443 và cấu hình Nginx', 'Thành công (2.5s): 2 cổng mở, Host ONLINE, HTTP Grade: B', 10, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days', 'Chuyên viên ATTT'),
(21, 2, 2, 'Kiểm tra bảo mật SSO Gateway', 'nmap', 'QUICK_SCAN', 'https://sso.vncert.vn', 'LOW', false, true, 'SUCCESS', 'Kiểm tra máy chủ xác thực Keycloak', 'Phát hiện dịch vụ Keycloak HTTPS', 'Thành công (1.8s): 1 cổng mở, Host ONLINE, HTTP Grade: A', 11, NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days', 'Chuyên viên ATTT'),

(30, 3, 1, 'Rà quét thiết bị mạng DMZ Gateway', 'nmap', 'TOP_100_PORTS', '192.168.54.1', 'LOW', false, true, 'SUCCESS', 'Quét cổng quản trị Router', 'Phát hiện cổng 22, 53, 80, 443', 'Thành công (3.1s): 4 cổng mở, Host ONLINE', 20, NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days', 'Chuyên viên ATTT'),

(40, 4, 1, 'Rà quét Web Cổng thanh toán & Dịch vụ', 'nmap', 'FULL_COMPREHENSIVE_SCAN', 'https://shop.vncert.vn', 'MEDIUM', false, true, 'SUCCESS', 'Kiểm thử cổng dịch vụ web và Tomcat backend', 'Phát hiện cổng 80, 443, 8080 và tệp sao lưu', 'Thành công (4.2s): 3 cổng mở, Host ONLINE, HTTP Grade: C', 30, NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', 'Chuyên viên ATTT'),

(50, 5, 1, 'Rà quét cổng dịch vụ CSDL Database', 'nmap', 'FULL_PORT_SCAN', '192.168.54.130', 'HIGH', false, true, 'SUCCESS', 'Rà quét cổng PostgreSQL 5432 và Redis 6379', 'Phát hiện Redis mở không mật khẩu', 'Thành công (2.2s): 3 cổng mở, Host ONLINE, CẢNH BÁO: Redis No Auth', 40, NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days', 'Chuyên viên ATTT'),

(60, 6, 1, 'Kiểm thử bảo mật API Gateway', 'nmap', 'FULL_COMPREHENSIVE_SCAN', 'https://api.vncert.vn', 'MEDIUM', false, true, 'SUCCESS', 'Rà quét endpoint API và Actuator', 'Phát hiện lộ lọt /actuator/env', 'Thành công (3.6s): 2 cổng mở, Host ONLINE, CẢNH BÁO: Actuator exposed', 50, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day', 'Chuyên viên ATTT'),

(70, 7, 1, 'Kiểm tra an ninh máy chủ GitLab', 'nmap', 'TOP_100_PORTS', '192.168.54.135', 'LOW', false, true, 'SUCCESS', 'Rà quét dịch vụ GitLab và Docker Registry', 'Phát hiện cổng 22, 80, 443, 5005', 'Thành công (2.8s): 4 cổng mở, Host ONLINE', 60, NOW() - INTERVAL '18 hours', NOW() - INTERVAL '18 hours', 'Chuyên viên ATTT'),

(80, 8, 1, 'Kiểm tra bảo mật Cổng tài liệu nội bộ', 'nmap', 'QUICK_SCAN', 'https://docs.vncert.vn', 'LOW', false, true, 'SUCCESS', 'Rà quét tiêu đề an ninh HTTP Docs', 'Cấu hình chuẩn Caddy TLS', 'Thành công (1.6s): 2 cổng mở, Host ONLINE, HTTP Grade: A', 70, NOW() - INTERVAL '12 hours', NOW() - INTERVAL '12 hours', 'Chuyên viên ATTT'),

(90, 9, 1, 'Rà soát cụm máy chủ SIEM', 'nmap', 'SERVICE_VERSION', '192.168.54.140', 'MEDIUM', false, true, 'SUCCESS', 'Kiểm tra cổng Elasticsearch và Kibana', 'Phát hiện cổng 22, 5044, 5601, 9200', 'Thành công (3.4s): 4 cổng mở, Host ONLINE', 80, NOW() - INTERVAL '8 hours', NOW() - INTERVAL '8 hours', 'Chuyên viên ATTT'),

(100, 10, 1, 'Kiểm tra an ninh cổng VPN SSL', 'nmap', 'FULL_COMPREHENSIVE_SCAN', 'https://vpn.vncert.vn', 'LOW', false, true, 'SUCCESS', 'Rà quét giao thức kết nối OpenVPN', 'Phát hiện cổng 443, 943, 1194', 'Thành công (2.8s): 3 cổng mở, Host ONLINE', 90, NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours', 'Chuyên viên ATTT')
ON CONFLICT (id) DO UPDATE SET 
    name = EXCLUDED.name,
    target = EXCLUDED.target,
    status = EXCLUDED.status,
    result_summary = EXCLUDED.result_summary,
    scan_task_id = EXCLUDED.scan_task_id;

-- 6. ASSESSMENT REPORTS
INSERT INTO assessment_reports (id, assessment_id, title, overall_risk, executive_summary, recommendations, critical_count, high_count, medium_count, low_count, info_count, total_findings, generated_by, generated_at) VALUES
(2, 2, 'Báo Cáo Đánh Giá An Toàn: Web Portal & SSO Gateway', 'MEDIUM',
 'Đợt kiểm thử an ninh ứng dụng Web Portal và máy chủ xác thực SSO hoàn thành tốt. Các giao dịch HTTPS và cơ chế SSO hoạt động ổn định, ghi nhận điểm yếu cấu hình Content-Security-Policy (CSP) và rò rỉ phiên bản Nginx.', 
 '- Bổ sung tiêu đề Content-Security-Policy.\n- Ẩn thông tin phiên bản Nginx.\n- Theo dõi các bản vá định kỳ cho Keycloak.', 0, 0, 2, 1, 0, 3, 'Chuyên viên ATTT', NOW() - INTERVAL '5 days' + INTERVAL '20 minutes'),

(3, 3, 'Báo Cáo Rà Soát An Toàn: Hạ tầng DMZ Gateway', 'MEDIUM',
 'Đã rà soát cổng mạng trên Gateway DMZ 192.168.54.1. Hệ thống mở các cổng cần thiết cho điều hướng mạng nhưng cần tắt kết nối giao diện quản trị LuCI qua HTTP cổng 80 không mã hóa.', 
 '- Buộc chuyển hướng toàn bộ kết nối HTTP sang HTTPS trên giao diện quản trị LuCI.\n- Giới hạn dải IP có thể kết nối cổng SSH 22.', 0, 0, 1, 1, 0, 2, 'Chuyên viên ATTT', NOW() - INTERVAL '4 days' + INTERVAL '15 minutes'),

(4, 4, 'Báo Cáo Đánh Giá An Toàn: Cổng dịch vụ trực tuyến & Thanh toán', 'HIGH',
 'CẢNH BÁO MỨC CAO: Đã phát hiện tệp tin nén sao lưu admin-backup.zip nằm tại thư mục gốc của Web Server. Kẻ tấn công có thể tải về để dịch ngược mã nguồn và chiếm quyền quản trị.', 
 '- Thu hồi và xóa ngay tệp admin-backup.zip trên máy chủ.\n- Ngăn chặn truy cập Internet trực tiếp vào cổng Tomcat 8080.\n- Kích hoạt cơ chế HSTS cho toàn bộ tên miền.', 0, 2, 1, 0, 0, 3, 'Chuyên viên ATTT', NOW() - INTERVAL '3 days' + INTERVAL '25 minutes'),

(5, 5, 'Báo Cáo Rà Soát Bảo Mật: Máy chủ Database & Cache Redis', 'CRITICAL',
 'NGHIÊM TRỌNG: Máy chủ cơ sở dữ liệu 192.168.54.130 đang mở dịch vụ Redis không yêu cầu mật khẩu xác thực. Cần xử lý khẩn cấp trước khi bị tin tặc cài mã độc đào tiền ảo hoặc chiếm quyền điều khiển root qua SSH authorized_keys.', 
 '- Thiết lập ngay mật khẩu mạnh trong redis.conf: requirepass <mat_khau>.\n- Đổi địa chỉ lắng nghe Redis thành bind 127.0.0.1.\n- Đóng cổng 5432 PostgreSQL đối với mạng ngoài qua firewall.', 1, 1, 1, 0, 0, 3, 'Chuyên viên ATTT', NOW() - INTERVAL '2 days' + INTERVAL '12 minutes'),

(6, 6, 'Báo Cáo Đánh Giá An Toàn: REST API Gateway', 'CRITICAL',
 'NGHIÊM TRỌNG: Endpoint giám sát Spring Boot Actuator (/actuator/env) bị để lộ công khai ra bên ngoài mà không yêu cầu xác thực người dùng. Dữ liệu nhạy cảm của biến môi trường hệ thống có thể bị trích xuất.', 
 '- Đóng ngay endpoint /actuator/env trong file cấu hình application.properties.\n- Phân quyền nghiêm ngặt cho cụm Actuator chỉ cho phép nội bộ truy cập.\n- Ẩn tài liệu Swagger UI trên production.', 1, 1, 1, 0, 0, 3, 'Chuyên viên ATTT', NOW() - INTERVAL '1 day' + INTERVAL '18 minutes'),

(7, 7, 'Báo Cáo Rà Soát An Ninh: Máy chủ GitLab & CI/CD', 'MEDIUM',
 'Máy chủ GitLab và Docker Registry hoạt động an toàn. Cần siết chặt xác thực 2FA cho các tài khoản nhà phát triển và kiểm tra phân quyền truy cập kho chứa Docker image.', 
 '- Kích hoạt bắt buộc 2FA cho mọi tài khoản có quyền truy cập repo.\n- Thiết lập xác thực Token cho Docker Registry cổng 5005.', 0, 0, 2, 0, 0, 2, 'Chuyên viên ATTT', NOW() - INTERVAL '18 hours' + INTERVAL '10 minutes'),

(8, 8, 'Báo Cáo Kiểm Tra An Toàn: Cổng tài liệu nội bộ', 'LOW',
 'Hệ thống tài liệu docs.vncert.vn tuân thủ xuất sắc các tiêu chuẩn bảo mật web hiện đại, đạt chuẩn A về Security Headers.', 
 '- Tiếp tục duy trì quy trình kiểm tra mã định kỳ.', 0, 0, 0, 1, 0, 1, 'Chuyên viên ATTT', NOW() - INTERVAL '12 hours' + INTERVAL '10 minutes'),

(9, 9, 'Báo Cáo Đánh Giá An Ninh: Cụm máy chủ SIEM', 'HIGH',
 'Cụm SIEM cần được bảo vệ nghiêm ngặt để chống lại hành vi xóa dấu vết của kẻ xâm nhập. Đã phát hiện cổng Elasticsearch 9200 cho phép truy vấn không yêu cầu xác thực người dùng ở mức mạng nội bộ.', 
 '- Bật xác thực Elasticsearch Security (X-Pack Security) và cấu hình mật khẩu cho user elastic.\n- Thiết lập giao thức HTTPS cho Kibana.', 0, 1, 1, 0, 0, 2, 'Chuyên viên ATTT', NOW() - INTERVAL '8 hours' + INTERVAL '15 minutes'),

(10, 10, 'Báo Cáo Kiểm Tra An Toàn: Gateway VPN SSL', 'MEDIUM',
 'Cổng kết nối từ xa VPN hoạt động tốt. Giao diện quản trị Admin cổng 943 cần được ẩn khỏi Internet công cộng để phòng tránh brute-force.', 
 '- Giới hạn cổng 943 chỉ cho phép truy cập từ mạng quản trị nội bộ.\n- Đảm bảo 100% tài khoản sử dụng xác thực đa yếu tố TOTP/2FA.', 0, 0, 2, 0, 0, 2, 'Chuyên viên ATTT', NOW() - INTERVAL '3 hours' + INTERVAL '8 minutes')
ON CONFLICT (id) DO UPDATE SET 
    title = EXCLUDED.title,
    overall_risk = EXCLUDED.overall_risk,
    executive_summary = EXCLUDED.executive_summary,
    recommendations = EXCLUDED.recommendations,
    critical_count = EXCLUDED.critical_count,
    high_count = EXCLUDED.high_count,
    medium_count = EXCLUDED.medium_count,
    low_count = EXCLUDED.low_count,
    total_findings = EXCLUDED.total_findings;

-- 7. VULNERABILITY FINDINGS
INSERT INTO vulnerability_findings (id, report_id, title, severity, target, port, service_name, cve_id, description, exploitation_vector, remediation, evidence, created_at) VALUES
(10, 2, 'Thiếu tiêu đề bảo mật Content-Security-Policy (CSP)', 'MEDIUM', 'https://portal.vncert.vn', 443, 'HTTPS', 'CWE-1021',
 'Trang web không thiết lập tiêu đề Content-Security-Policy, làm tăng nguy cơ bị tấn công chèn mã độc Cross-Site Scripting (XSS).',
 'Kẻ tấn công có thể chèn mã JavaScript độc hại vào trang web qua các trường phản hồi chưa được lọc kỹ.',
 'Bổ sung tiêu đề Content-Security-Policy trong phản hồi của Nginx.',
 'Header Content-Security-Policy không tồn tại trong HTTP response', NOW() - INTERVAL '5 days'),

(11, 2, 'Lộ thông tin phiên bản chi tiết Web Server trong Server Header', 'LOW', 'https://portal.vncert.vn', 443, 'HTTPS', 'CWE-200',
 'Tiêu đề phản hồi chứa chính xác chuỗi nginx/1.22.1, giúp kẻ tấn công thu thập thông tin và tìm kiếm CVE phù hợp.',
 'Kẻ tấn công tra cứu cơ sở dữ liệu lỗ hổng của phiên bản Nginx 1.22.1.',
 'Thêm cấu hình server_tokens off; trong block http của nginx.conf.',
 'Server: nginx/1.22.1', NOW() - INTERVAL '5 days'),

(20, 3, 'Giao diện quản trị thiết bị định tuyến cho phép truy cập qua HTTP không mã hóa', 'MEDIUM', '192.168.54.1', 80, 'HTTP LuCI', 'CWE-319',
 'Cổng 80 cho phép đăng nhập vào trang quản trị OpenWrt LuCI mà không mã hóa, mật khẩu có thể bị bắt lén (Sniffing) trên mạng LAN.',
 'Kẻ tấn công cùng mạng LAN dùng Wireshark hoặc ARP Spoofing để bắt gói tin chứa mật khẩu quản trị.',
 'Cấu hình chuyển hướng 301 tự động từ HTTP cổng 80 sang HTTPS cổng 443.',
 'HTTP/1.1 200 OK với form đăng nhập LuCI qua plain-text', NOW() - INTERVAL '4 days'),

(30, 4, 'Để lộ tệp tin sao lưu mã nguồn nhạy cảm admin-backup.zip', 'HIGH', 'https://shop.vncert.vn', 443, 'HTTPS', 'CWE-530',
 'Phát hiện tệp nén admin-backup.zip nằm tại thư mục công khai của website, cho phép tải xuống trực tiếp không cần đăng nhập.',
 'Kẻ tấn công tải tệp zip, giải nén đọc mã nguồn PHP, tìm thấy thông tin cấu hình kết nối CSDL và khóa bí mật API.',
 'Xóa tệp zip ngay lập tức khỏi thư mục web root và rà soát lại toàn bộ cây thư mục.',
 'GET /admin-backup.zip HTTP/1.1 trả về mã 200 OK kèm dung lượng 42MB', NOW() - INTERVAL '3 days'),

(31, 4, 'Thiếu cơ chế bảo vệ HTTP Strict Transport Security (HSTS)', 'MEDIUM', 'https://shop.vncert.vn', 80, 'HTTP', 'CWE-319',
 'Website không sử dụng HSTS, dẫn đến nguy cơ người dùng bị tấn công SSL Stripping khi kết nối lần đầu.',
 'Kẻ tấn công chặn kết nối cổng 80 và hạ cấp phiên giao dịch từ HTTPS xuống HTTP.',
 'Bổ sung tiêu đề Strict-Transport-Security: max-age=31536000; includeSubDomains.',
 'Không phát hiện tiêu đề Strict-Transport-Security trong HTTP Header', NOW() - INTERVAL '3 days'),

(40, 5, 'Dịch vụ Redis mở không yêu cầu mật khẩu xác thực (Unauthenticated Access)', 'CRITICAL', '192.168.54.130', 6379, 'Redis', 'CVE-2015-4335',
 'Cổng 6379 Redis lắng nghe trên mọi giao diện mạng (0.0.0.0) và không bật xác thực mật khẩu. Bất kỳ ai cũng có thể thực thi lệnh redis-cli.',
 'Kẻ tấn công kết nối redis-cli, thực hiện ghi đè tệp /root/.ssh/authorized_keys để đăng nhập SSH dưới quyền root máy chủ.',
 'Thiết lập requirepass trong file cấu hình redis.conf và giới hạn bind 127.0.0.1.',
 'Kết nối thử nghiệm qua lệnh PING trả về PONG thành công mà không cần lệnh AUTH', NOW() - INTERVAL '2 days'),

(41, 5, 'Dịch vụ PostgreSQL lắng nghe trên giao diện mạng công khai', 'MEDIUM', '192.168.54.130', 5432, 'PostgreSQL', 'CWE-284',
 'Cổng 5432 mở công khai ra toàn mạng nội bộ, làm gia tăng nguy cơ bị brute-force tài khoản postgres.',
 'Kẻ tấn công thực hiện quét cổng và chạy từ điển tấn công dò mật khẩu tài khoản quản trị CSDL.',
 'Cấu hình listen_addresses trong postgresql.conf và siết chặt dải IP trong pg_hba.conf.',
 'Nmap phát hiện cổng 5432/tcp open postgresql', NOW() - INTERVAL '2 days'),

(50, 6, 'Để lộ endpoint nhạy cảm Spring Boot Actuator /actuator/env', 'CRITICAL', 'https://api.vncert.vn', 443, 'HTTPS', 'CVE-2022-22965',
 'Endpoint /actuator/env hiển thị danh sách toàn bộ thuộc tính môi trường bao gồm các mật khẩu, token dịch vụ và đường dẫn hệ thống.',
 'Kẻ tấn công gửi GET /actuator/env, trích xuất chuỗi kết nối Database và JWT Secret Key để tạo token giả mạo quyền quản trị viên.',
 'Thêm thuộc tính management.endpoints.web.exposure.exclude=env trong tệp application.properties.',
 'GET /actuator/env trả về danh sách systemEnvironment và propertySources', NOW() - INTERVAL '1 day'),

(51, 6, 'Tài liệu API Swagger UI hiển thị công khai trên môi trường vận hành', 'LOW', 'https://api.vncert.vn', 443, 'HTTPS', 'CWE-200',
 'Trang /swagger-ui.html không yêu cầu xác thực, giúp kẻ xấu nắm rõ toàn bộ cấu trúc API và các tham số truyền vào.',
 'Kẻ tấn công phân tích danh sách API để tìm ra các endpoint ẩn có lỗ hổng IDOR hoặc SQL Injection.',
 'Tắt Swagger trên môi trường Production bằng cách cấu hình springdoc.api-docs.enabled=false.',
 'GET /swagger-ui.html trả về giao diện Swagger UI hoàn chỉnh', NOW() - INTERVAL '1 day'),

(60, 7, 'Cổng Docker Registry 5005 cho phép truy vấn không yêu cầu xác thực', 'MEDIUM', '192.168.54.135', 5005, 'Docker Registry', 'CWE-306',
 'Cổng 5005 trả về danh sách các image và tag mà không cần xác thực tài khoản.',
 'Kẻ tấn công pull các container image nội bộ về phân tích mã nguồn và tìm kiếm hardcoded credentials.',
 'Cấu hình xác thực Basic Auth hoặc tích hợp xác thực Token qua GitLab cho Docker Registry.',
 'GET /v2/_catalog trả về danh sách repositories', NOW() - INTERVAL '18 hours'),

(80, 9, 'Dịch vụ Elasticsearch REST API cho phép truy vấn không cần mật khẩu', 'HIGH', '192.168.54.140', 9200, 'Elasticsearch', 'CWE-306',
 'Cổng 9200 Elasticsearch cho phép thực hiện các truy vấn đọc chỉ mục log hệ thống mà không cần xác thực.',
 'Kẻ tấn công có thể đọc toàn bộ log hệ thống để tìm kiếm thông tin tài khoản người dùng hoặc xóa chỉ mục log để phi tang.',
 'Kích hoạt xpack.security.enabled: true và đặt mật khẩu bảo vệ cho cụm Elasticsearch.',
 'GET http://192.168.54.140:9200 trả về thông tin cluster "cluster_name": "siem-cluster"', NOW() - INTERVAL '8 hours'),

(90, 10, 'Giao diện quản trị OpenVPN Admin Portal cổng 943 mở ra ngoài mạng', 'MEDIUM', 'https://vpn.vncert.vn', 943, 'HTTPS Admin', 'CWE-284',
 'Giao diện đăng nhập quản trị viên của máy chủ VPN mở công khai, dễ bị tấn công vét cạn mật khẩu từ Internet.',
 'Kẻ tấn công chạy các cuộc tấn công Brute-force mật khẩu tài khoản admin VPN từ xa.',
 'Cấu hình tường lửa chỉ cho phép các IP nội bộ truy cập cổng 943.',
 'Giao diện OpenVPN Access Server Admin Web Login phản hồi mã 200 OK trên cổng 943', NOW() - INTERVAL '3 hours')
ON CONFLICT (id) DO UPDATE SET 
    title = EXCLUDED.title,
    severity = EXCLUDED.severity,
    target = EXCLUDED.target,
    port = EXCLUDED.port,
    service_name = EXCLUDED.service_name,
    cve_id = EXCLUDED.cve_id,
    description = EXCLUDED.description,
    exploitation_vector = EXCLUDED.exploitation_vector,
    remediation = EXCLUDED.remediation;

-- 8. SYNCHRONIZE ALL SEQUENCES TO PREVENT ID CONFLICTS ON NEW INSERTS
SELECT setval('assessments_id_seq', COALESCE((SELECT MAX(id) FROM assessments), 1));
SELECT setval('scopes_id_seq', COALESCE((SELECT MAX(id) FROM scopes), 1));
SELECT setval('assessment_plans_id_seq', COALESCE((SELECT MAX(id) FROM assessment_plans), 1));
SELECT setval('plan_steps_id_seq', COALESCE((SELECT MAX(id) FROM plan_steps), 1));
SELECT setval('scan_tasks_id_seq', COALESCE((SELECT MAX(id) FROM scan_tasks), 1));
SELECT setval('assessment_reports_id_seq', COALESCE((SELECT MAX(id) FROM assessment_reports), 1));
SELECT setval('vulnerability_findings_id_seq', COALESCE((SELECT MAX(id) FROM vulnerability_findings), 1));

COMMIT;
