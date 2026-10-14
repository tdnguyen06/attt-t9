package com.example.backend.modules.recon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Slf4j
public class TechStackDetectionService {

    private final HttpClient httpClient;

    public TechStackDetectionService() {
        this.httpClient = createPermissiveHttpClient();
    }

    public TechStackScanResult detectTechStack(String target) {
        String cleanTarget = normalizeUrl(target);
        List<TechStackItemDto> items = new ArrayList<>();
        Map<String, TechStackItemDto> deduplicated = new LinkedHashMap<>();

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(cleanTarget))
                    .timeout(Duration.ofSeconds(6))
                    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
                    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            HttpHeaders headers = response.headers();
            String body = response.body() != null ? response.body() : "";

            // 1. Phân tích Headers
            analyzeHeaders(headers, deduplicated);

            // 2. Phân tích HTML Content & Meta & Script tags
            analyzeHtmlContent(body, deduplicated);

            // 3. Phân tích Cookies
            analyzeCookies(headers, deduplicated);

            // 4. Phát hiện dịch vụ theo cổng
            detectNonHttpServices(target, deduplicated);

            items.addAll(deduplicated.values());

            String summary = String.format("Nhận diện thành công %d công nghệ đang vận hành trên mục tiêu.", items.size());

            return TechStackScanResult.builder()
                    .target(cleanTarget)
                    .technologies(items)
                    .summary(summary)
                    .success(true)
                    .build();

        } catch (Exception e) {
            log.info("Mục tiêu {} không phản hồi HTTP chuẩn ({}), tiến hành dò xét dịch vụ mạng...", cleanTarget, e.getMessage());
            detectNonHttpServices(target, deduplicated);
            List<TechStackItemDto> fallbackItems = new ArrayList<>(deduplicated.values());
            String summary = fallbackItems.isEmpty()
                    ? "Đã phân tích mục tiêu (Dịch vụ không sử dụng giao thức HTTP web tiêu chuẩn)."
                    : String.format("Nhận diện thành công %d dịch vụ mạng qua phân tích cổng và giao thức.", fallbackItems.size());

            return TechStackScanResult.builder()
                    .target(cleanTarget)
                    .technologies(fallbackItems)
                    .summary(summary)
                    .success(true)
                    .errorMessage(e.getMessage())
                    .build();
        }
    }

    private void detectNonHttpServices(String target, Map<String, TechStackItemDto> detected) {
        if (target == null) return;
        String t = target.toLowerCase();

        Integer port = null;
        try {
            Matcher m = Pattern.compile("(?::)(\\d+)(?:/|$)").matcher(target);
            if (m.find()) {
                port = Integer.parseInt(m.group(1));
            }
        } catch (Exception ignored) {}

        if ((port != null && (port == 389 || port == 636)) || (t.contains("ldap") && !t.contains("8888"))) {
            addTech(detected, "Active Directory / LDAP", "DIRECTORY_SERVICE", "HIGH", "Phát hiện cổng kết nối LDAP (TCP 389 / 636)");
            addTech(detected, "LDAP Protocol", "AUTHENTICATION", "HIGH", "Dịch vụ định danh và xác thực thư mục người dùng");
        }
        if ((port != null && port == 88) || (t.contains("kerberos") && !t.contains("8888"))) {
            addTech(detected, "Kerberos KDC", "SECURITY_AUTH", "HIGH", "Cổng dịch vụ xác thực vé Kerberos (Port 88)");
        }
        if ((port != null && port == 445) || (t.contains("smb") && !t.contains("8888"))) {
            addTech(detected, "SMB / Windows File Sharing", "NETWORK_SERVICE", "HIGH", "Giao thức chia sẻ tệp tin SMB (Port 445)");
        }
        if ((port != null && (port == 5432 || port == 15432)) || (t.contains("postgres") && !t.contains("8888"))) {
            addTech(detected, "PostgreSQL Database", "DATABASE", "HIGH", "Hệ quản trị cơ sở dữ liệu PostgreSQL (Port 5432)");
        }
    }

    private void analyzeHeaders(HttpHeaders headers, Map<String, TechStackItemDto> detected) {
        // Server banner
        headers.firstValue("server").ifPresent(server -> {
            String s = server.toLowerCase();
            if (s.contains("vercel")) {
                addTech(detected, "Vercel Edge Network", "CDN_WAF", "HIGH", "Header Server: " + server);
            } else if (s.contains("cloudflare")) {
                addTech(detected, "Cloudflare Edge", "CDN_WAF", "HIGH", "Header Server: " + server);
            } else if (s.contains("nginx")) {
                addTech(detected, "Nginx Web Server", "WEB_SERVER", "HIGH", "Header Server: " + server);
            } else if (s.contains("apache-coyote") || s.contains("tomcat")) {
                addTech(detected, "Apache Tomcat", "APP_SERVER", "HIGH", "Header Server: " + server);
            } else if (s.contains("apache")) {
                addTech(detected, "Apache HTTP Server", "WEB_SERVER", "HIGH", "Header Server: " + server);
            } else if (s.contains("microsoft-iis") || s.contains("iis")) {
                addTech(detected, "Microsoft IIS", "WEB_SERVER", "HIGH", "Header Server: " + server);
            } else if (s.contains("caddy")) {
                addTech(detected, "Caddy Server", "WEB_SERVER", "HIGH", "Header Server: " + server);
            } else {
                addTech(detected, server, "WEB_SERVER", "MEDIUM", "Header Server: " + server);
            }
        });

        // X-Powered-By
        headers.firstValue("x-powered-by").ifPresent(pb -> {
            String p = pb.toLowerCase();
            if (p.contains("express")) {
                addTech(detected, "Express.js", "BACKEND", "HIGH", "Header X-Powered-By: " + pb);
                addTech(detected, "Node.js", "BACKEND", "HIGH", "Kèm theo Express framework");
            } else if (p.contains("php")) {
                addTech(detected, "PHP", "BACKEND", "HIGH", "Header X-Powered-By: " + pb);
            } else if (p.contains("asp.net")) {
                addTech(detected, "ASP.NET", "BACKEND", "HIGH", "Header X-Powered-By: " + pb);
            } else if (p.contains("next.js")) {
                addTech(detected, "Next.js", "FRONTEND_FRAMEWORK", "HIGH", "Header X-Powered-By: " + pb);
            } else {
                addTech(detected, pb, "BACKEND", "MEDIUM", "Header X-Powered-By: " + pb);
            }
        });

        // Vercel specific
        if (headers.firstValue("x-vercel-id").isPresent() || headers.firstValue("x-vercel-cache").isPresent()) {
            addTech(detected, "Vercel Platform", "CDN_WAF", "HIGH", "Header x-vercel-id nhận diện nền tảng Vercel");
        }

        // Cloudflare
        if (headers.firstValue("cf-ray").isPresent()) {
            addTech(detected, "Cloudflare WAF / CDN", "CDN_WAF", "HIGH", "Header cf-ray");
        }

        // AWS CloudFront
        if (headers.firstValue("x-amz-cf-id").isPresent() || headers.firstValue("via").filter(v -> v.contains("CloudFront")).isPresent()) {
            addTech(detected, "Amazon CloudFront", "CDN_WAF", "HIGH", "Header CloudFront detection");
        }
    }

    private void analyzeHtmlContent(String html, Map<String, TechStackItemDto> detected) {
        if (html == null || html.isBlank()) return;

        String lower = html.toLowerCase();

        // Astro
        if (lower.contains("data-astro-cid") || lower.contains("astro-island") || lower.contains("astro.build")) {
            addTech(detected, "Astro Framework", "FRONTEND_FRAMEWORK", "HIGH", "HTML attributes: data-astro-cid");
        }

        // Next.js
        if (lower.contains("/_next/static/") || lower.contains("__next_data__") || lower.contains("id=\"__next\"")) {
            addTech(detected, "Next.js (React Framework)", "FRONTEND_FRAMEWORK", "HIGH", "HTML script bundle: /_next/static");
            addTech(detected, "React", "FRONTEND_FRAMEWORK", "HIGH", "Thành phần phụ thuộc của Next.js");
        }

        // React
        if (lower.contains("data-reactroot") || lower.contains("react.production.min.js") || lower.contains("react-dom")) {
            addTech(detected, "React UI Library", "FRONTEND_FRAMEWORK", "HIGH", "React DOM footprint trong HTML");
        }

        // Vue.js & Nuxt.js
        if (lower.contains("data-v-") || lower.contains("__vue__") || lower.contains("vue.min.js")) {
            addTech(detected, "Vue.js", "FRONTEND_FRAMEWORK", "HIGH", "Vue Scoped CSS attributes (data-v-*)");
        }
        if (lower.contains("__nuxt") || lower.contains("/_nuxt/")) {
            addTech(detected, "Nuxt.js", "FRONTEND_FRAMEWORK", "HIGH", "Nuxt.js app bundle (/_nuxt/)");
        }

        // Angular
        if (lower.contains("ng-version") || lower.contains("ng-app") || lower.contains("angular.min.js")) {
            addTech(detected, "Angular", "FRONTEND_FRAMEWORK", "HIGH", "Thuộc tính ng-version trong mã HTML");
        }

        // WordPress
        if (lower.contains("/wp-content/") || lower.contains("/wp-includes/") || lower.contains("wp-block")) {
            addTech(detected, "WordPress CMS", "CMS", "HIGH", "Đường dẫn tài nguyên /wp-content/ và /wp-includes/");
            addTech(detected, "PHP", "BACKEND", "HIGH", "Nền tảng của WordPress");
        }

        // Tailwind CSS
        if (lower.contains("tailwind") || (lower.contains("flex") && lower.contains("grid") && lower.contains("rounded-") && lower.contains("bg-slate-"))) {
            addTech(detected, "Tailwind CSS", "FRONTEND_FRAMEWORK", "MEDIUM", "Class utilities & style signature");
        }

        // Bootstrap
        if (lower.contains("bootstrap.min.css") || lower.contains("data-bs-toggle") || lower.contains("class=\"btn btn-primary\"")) {
            addTech(detected, "Bootstrap UI", "FRONTEND_FRAMEWORK", "HIGH", "Bootstrap CSS bundle và data-bs-* attributes");
        }

        // jQuery
        if (lower.contains("jquery.min.js") || lower.contains("jquery-")) {
            addTech(detected, "jQuery", "FRONTEND_FRAMEWORK", "HIGH", "Thư viện jQuery được nạp trong thẻ script");
        }

        // Google Analytics & GTM
        if (lower.contains("googletagmanager.com/gtm.js") || lower.contains("google-analytics.com/analytics.js") || lower.contains("gtag('js'")) {
            addTech(detected, "Google Tag Manager / Analytics", "ANALYTICS", "HIGH", "Tracking script GTM / gtag");
        }

        // Generator meta tag
        Pattern metaGen = Pattern.compile("<meta\\s+name=[\"']generator[\"']\\s+content=[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE);
        Matcher m = metaGen.matcher(html);
        if (m.find()) {
            String gen = m.group(1);
            addTech(detected, gen, "CMS", "HIGH", "Meta Tag Generator: " + gen);
        }
    }

    private void analyzeCookies(HttpHeaders headers, Map<String, TechStackItemDto> detected) {
        List<String> setCookies = headers.allValues("set-cookie");
        for (String cookie : setCookies) {
            String c = cookie.toLowerCase();
            if (c.contains("phpsessid")) {
                addTech(detected, "PHP", "BACKEND", "HIGH", "Cookie định danh: PHPSESSID");
            } else if (c.contains("jsessionid")) {
                addTech(detected, "Java / Spring Boot", "BACKEND", "HIGH", "Cookie định danh: JSESSIONID");
            } else if (c.contains("csrftoken") || c.contains("sessionid")) {
                addTech(detected, "Django / Python", "BACKEND", "MEDIUM", "Cookie định danh: csrftoken / sessionid");
            } else if (c.contains("laravel_session") || c.contains("xsrf-token")) {
                addTech(detected, "Laravel (PHP)", "BACKEND", "HIGH", "Cookie định danh: laravel_session");
            } else if (c.contains("asp.net_sessionid") || c.contains(".aspnetauth")) {
                addTech(detected, "ASP.NET / C#", "BACKEND", "HIGH", "Cookie định danh: ASP.NET_SessionId");
            }
        }
    }

    private void addTech(Map<String, TechStackItemDto> map, String name, String category, String confidence, String evidence) {
        if (name == null || name.isBlank()) return;
        String key = name.trim().toLowerCase();
        if (!map.containsKey(key)) {
            map.put(key, TechStackItemDto.builder()
                    .name(name.trim())
                    .category(category)
                    .confidence(confidence)
                    .evidence(evidence)
                    .build());
        }
    }

    private String normalizeUrl(String target) {
        if (target == null || target.isBlank()) return "http://localhost:8080";
        String trimmed = target.trim();
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            String lower = trimmed.toLowerCase();
            if (lower.startsWith("localhost") || lower.startsWith("127.0.0.1") || lower.startsWith("192.168.") || lower.startsWith("10.") || lower.startsWith("172.") || lower.contains(":") || !lower.contains(".")) {
                return "http://" + trimmed;
            }
            return "https://" + trimmed;
        }
        return trimmed;
    }

    private HttpClient createPermissiveHttpClient() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            return HttpClient.newBuilder()
                    .sslContext(sslContext)
                    .connectTimeout(Duration.ofSeconds(6))
                    .followRedirects(HttpClient.Redirect.ALWAYS)
                    .build();
        } catch (Exception e) {
            return HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(6))
                    .followRedirects(HttpClient.Redirect.ALWAYS)
                    .build();
        }
    }
}
