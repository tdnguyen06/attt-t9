package com.example.backend.modules.recon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
@Slf4j
public class HttpSecurityScannerService {

    private static final Map<String, HeaderRule> SECURITY_RULES = new LinkedHashMap<>();

    static {
        SECURITY_RULES.put("Strict-Transport-Security", new HeaderRule(
                "HIGH",
                "Bảo vệ chống tấn công SSL-stripping và Man-in-the-middle bằng cách ép buộc trình duyệt chỉ kết nối qua HTTPS.",
                "Thêm header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ));
        SECURITY_RULES.put("Content-Security-Policy", new HeaderRule(
                "HIGH",
                "Ngăn chặn tấn công Cross-Site Scripting (XSS) và Data Injection bằng cách giới hạn nguồn tải tài nguyên.",
                "Thêm header: Content-Security-Policy: default-src 'self'; script-src 'self'..."
        ));
        SECURITY_RULES.put("X-Frame-Options", new HeaderRule(
                "MEDIUM",
                "Chống tấn công Clickjacking bằng cách kiểm soát trang web có được nhúng trong iframe không.",
                "Thêm header: X-Frame-Options: DENY hoặc SAMEORIGIN"
        ));
        SECURITY_RULES.put("X-Content-Type-Options", new HeaderRule(
                "MEDIUM",
                "Ngăn chặn MIME-type sniffing từ trình duyệt.",
                "Thêm header: X-Content-Type-Options: nosniff"
        ));
        SECURITY_RULES.put("Referrer-Policy", new HeaderRule(
                "LOW",
                "Kiểm soát lượng thông tin Referrer được gửi kèm khi người dùng chuyển hướng link.",
                "Thêm header: Referrer-Policy: strict-origin-when-cross-origin"
        ));
        SECURITY_RULES.put("Permissions-Policy", new HeaderRule(
                "LOW",
                "Giới hạn quyền truy cập API phần cứng như Camera, Microphone, Geolocation.",
                "Thêm header: Permissions-Policy: camera=(), microphone=(), geolocation=()"
        ));
    }

    private static record HeaderRule(String severity, String description, String recommendation) {}

    public HttpSecurityScanResult scanHttpSecurity(String inputUrl) {
        String targetUrl = normalizeUrl(inputUrl);
        List<HttpSecurityHeaderDto> headersList = new ArrayList<>();
        List<String> missingCritical = new ArrayList<>();
        List<String> vulnerabilities = new ArrayList<>();

        int score = 100;

        try {
            HttpClient client = HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .followRedirects(HttpClient.Redirect.ALWAYS)
                    .connectTimeout(Duration.ofSeconds(6))
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ATTT-Recon-Scanner/1.0")
                    .timeout(Duration.ofSeconds(10))
                    .GET()
                    .build();

            HttpResponse<Void> response = client.send(request, HttpResponse.BodyHandlers.discarding());
            HttpHeaders responseHeaders = response.headers();

            String serverBanner = responseHeaders.firstValue("Server").orElse(null);
            String poweredBy = responseHeaders.firstValue("X-Powered-By").orElse(null);

            if (serverBanner != null) {
                vulnerabilities.add("Lộ thông tin Server banner: " + serverBanner);
                score -= 5;
            }
            if (poweredBy != null) {
                vulnerabilities.add("Lộ framework/ngôn ngữ qua X-Powered-By: " + poweredBy);
                score -= 5;
            }

            // Check security headers
            for (Map.Entry<String, HeaderRule> entry : SECURITY_RULES.entrySet()) {
                String headerName = entry.getKey();
                HeaderRule rule = entry.getValue();
                Optional<String> val = responseHeaders.firstValue(headerName);

                if (val.isPresent()) {
                    headersList.add(HttpSecurityHeaderDto.builder()
                            .headerName(headerName)
                            .value(val.get())
                            .present(true)
                            .severity("INFO")
                            .description(rule.description())
                            .recommendation("Đã cấu hình hợp lệ.")
                            .build());
                } else {
                    headersList.add(HttpSecurityHeaderDto.builder()
                            .headerName(headerName)
                            .value(null)
                            .present(false)
                            .severity(rule.severity())
                            .description(rule.description())
                            .recommendation(rule.recommendation())
                            .build());

                    if ("HIGH".equals(rule.severity())) {
                        missingCritical.add(headerName);
                        score -= 20;
                    } else if ("MEDIUM".equals(rule.severity())) {
                        score -= 10;
                    } else {
                        score -= 5;
                    }
                }
            }

            // Inspect SSL Certificate if HTTPS
            SslCertificateInfoDto sslInfo = null;
            if (targetUrl.startsWith("https://")) {
                sslInfo = inspectSslCertificate(targetUrl);
                if (sslInfo != null && sslInfo.isExpired()) {
                    vulnerabilities.add("Chứng chỉ SSL/TLS đã hết hạn!");
                    score -= 30;
                }
            } else {
                vulnerabilities.add("Mục tiêu đang sử dụng HTTP không mã hóa (Không có SSL/TLS).");
                score -= 30;
            }

            score = Math.max(0, Math.min(100, score));
            String grade = calculateGrade(score);

            return HttpSecurityScanResult.builder()
                    .url(targetUrl)
                    .statusCode(response.statusCode())
                    .serverBanner(serverBanner != null ? serverBanner : "Không xác định")
                    .poweredByBanner(poweredBy != null ? poweredBy : "Không xác định")
                    .grade(grade)
                    .score(score)
                    .headers(headersList)
                    .sslInfo(sslInfo)
                    .missingCriticalHeaders(missingCritical)
                    .vulnerabilities(vulnerabilities)
                    .success(true)
                    .build();

        } catch (Exception e) {
            log.warn("Lỗi khi quét HTTP Security cho {}: {}", targetUrl, e.getMessage());
            return HttpSecurityScanResult.builder()
                    .url(targetUrl)
                    .grade("F")
                    .score(0)
                    .success(false)
                    .errorMessage("Không thể kết nối tới mục tiêu: " + e.getMessage())
                    .build();
        }
    }

    private SslCertificateInfoDto inspectSslCertificate(String httpsUrl) {
        try {
            URL url = new URL(httpsUrl);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);
            conn.connect();

            Certificate[] certs = conn.getServerCertificates();
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                X509Certificate x509 = (X509Certificate) certs[0];
                Date notAfter = x509.getNotAfter();
                long days = ChronoUnit.DAYS.between(Instant.now(), notAfter.toInstant());
                boolean expired = days < 0;

                List<String> sans = new ArrayList<>();
                try {
                    Collection<List<?>> altNames = x509.getSubjectAlternativeNames();
                    if (altNames != null) {
                        for (List<?> item : altNames) {
                            if (item.size() >= 2 && item.get(1) != null) {
                                sans.add(item.get(1).toString());
                            }
                        }
                    }
                } catch (Exception ignored) {}

                return SslCertificateInfoDto.builder()
                        .subject(x509.getSubjectX500Principal().getName())
                        .issuer(x509.getIssuerX500Principal().getName())
                        .validFrom(x509.getNotBefore().toString())
                        .validTo(notAfter.toString())
                        .daysRemaining(Math.max(0, days))
                        .expired(expired)
                        .signatureAlgorithm(x509.getSigAlgName())
                        .subjectAlternativeNames(sans)
                        .build();
            }
        } catch (Exception e) {
            log.debug("Không thể trích xuất SSL cert từ {}: {}", httpsUrl, e.getMessage());
        }
        return null;
    }

    private String calculateGrade(int score) {
        if (score >= 90) return "A+";
        if (score >= 80) return "A";
        if (score >= 70) return "B";
        if (score >= 55) return "C";
        if (score >= 40) return "D";
        return "F";
    }

    private String normalizeUrl(String input) {
        if (input == null || input.isBlank()) return "http://localhost:8080";
        String trimmed = input.trim();
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            String lower = trimmed.toLowerCase();
            if (lower.startsWith("localhost") || lower.startsWith("127.0.0.1") || lower.startsWith("192.168.") || lower.startsWith("10.") || lower.startsWith("172.") || lower.contains(":") || !lower.contains(".")) {
                return "http://" + trimmed;
            }
            return "https://" + trimmed;
        }
        return trimmed;
    }
}
