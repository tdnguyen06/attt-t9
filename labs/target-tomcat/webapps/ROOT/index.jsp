<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Apache Tomcat 9.0 Test Target - ATTT Portal</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; margin: 0; }
        .card { max-width: 650px; margin: 40px auto; background: #1e293b; border-radius: 12px; padding: 24px; border: 1px solid #334155; }
        .badge { background: #f59e0b; color: #000; padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: bold; }
        h1 { margin-top: 12px; font-size: 24px; color: #fbbf24; }
        p { color: #94a3b8; line-height: 1.6; }
        code { background: #0f172a; padding: 2px 6px; border-radius: 4px; color: #38bdf8; }
    </style>
</head>
<body>
    <div class="card">
        <span class="badge">Apache Tomcat 9.x Target Lab</span>
        <h1>Máy Chủ Mục Tiêu Kiểm Thử - Apache Tomcat</h1>
        <p>Phiên bản ứng dụng chạy trên Apache Tomcat nhằm mục đích kiểm thử tính năng rà quét ATTT, nhận diện phiên bản Server Header, cổng AJP 8009, CVE Ghostcat và quét lỗ hổng ứng dụng Java Web.</p>
        <ul>
            <li><strong>Port HTTP:</strong> 8080 (Host mapping: <code>http://localhost:8888/</code>)</li>
            <li><strong>Port AJP:</strong> 8009 (Host mapping: <code>localhost:8009</code>)</li>
            <li><strong>Server Info:</strong> <%= application.getServerInfo() %></li>
            <li><strong>Current Server Time:</strong> <%= new java.util.Date() %></li>
        </ul>
    </div>
</body>
</html>
