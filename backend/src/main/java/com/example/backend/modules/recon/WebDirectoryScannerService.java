package com.example.backend.modules.recon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

@Service
@Slf4j
public class WebDirectoryScannerService {

    private static final List<ScanEntry> DEFAULT_WORDLIST = List.of(
            // Admin & Management Panels
            new ScanEntry("/admin", "ADMIN", "HIGH", true),
            new ScanEntry("/admin/login", "ADMIN", "HIGH", true),
            new ScanEntry("/administrator", "ADMIN", "HIGH", true),
            new ScanEntry("/phpmyadmin/", "ADMIN", "HIGH", true),
            new ScanEntry("/wp-admin/", "ADMIN", "HIGH", true),
            new ScanEntry("/wp-login.php", "ADMIN", "HIGH", true),
            new ScanEntry("/console", "ADMIN", "HIGH", true),
            new ScanEntry("/manager/html", "ADMIN", "HIGH", true),

            // Sensitive Config & Source Code Leaks
            new ScanEntry("/.env", "CONFIG", "HIGH", true),
            new ScanEntry("/.git/HEAD", "CONFIG", "HIGH", true),
            new ScanEntry("/.gitignore", "CONFIG", "MEDIUM", true),
            new ScanEntry("/config.json", "CONFIG", "HIGH", true),
            new ScanEntry("/application.properties", "CONFIG", "HIGH", true),
            new ScanEntry("/application.yml", "CONFIG", "HIGH", true),
            new ScanEntry("/web.config", "CONFIG", "HIGH", true),

            // Backups
            new ScanEntry("/backup.zip", "BACKUP", "HIGH", true),
            new ScanEntry("/backup.sql", "BACKUP", "HIGH", true),
            new ScanEntry("/db.sql", "BACKUP", "HIGH", true),
            new ScanEntry("/backup.tar.gz", "BACKUP", "HIGH", true),

            // APIs & Spring Boot Actuator
            new ScanEntry("/api", "API", "LOW", false),
            new ScanEntry("/api/v1", "API", "LOW", false),
            new ScanEntry("/swagger-ui.html", "API", "MEDIUM", false),
            new ScanEntry("/swagger-ui/index.html", "API", "MEDIUM", false),
            new ScanEntry("/v3/api-docs", "API", "MEDIUM", false),
            new ScanEntry("/actuator", "API", "HIGH", true),
            new ScanEntry("/actuator/health", "API", "LOW", false),
            new ScanEntry("/actuator/env", "API", "HIGH", true),
            new ScanEntry("/actuator/metrics", "API", "MEDIUM", false),

            // General & Recon Files
            new ScanEntry("/robots.txt", "GENERAL", "INFO", false),
            new ScanEntry("/sitemap.xml", "GENERAL", "INFO", false),
            new ScanEntry("/.well-known/security.txt", "GENERAL", "INFO", false),
            new ScanEntry("/server-status", "GENERAL", "MEDIUM", true)
    );

    private static record ScanEntry(String path, String category, String riskLevel, boolean isSensitive) {}

    public WebDirectoryScanResult scanDirectories(String inputUrl) {
        long startTime = System.currentTimeMillis();
        String baseUrl = cleanBaseUrl(inputUrl);

        List<WebDirResultDto> discovered = new CopyOnWriteArrayList<>();
        int sensitiveCount = 0;

        HttpClient client = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(4))
                .build();

        ExecutorService executor = Executors.newFixedThreadPool(8);
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (ScanEntry entry : DEFAULT_WORDLIST) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                String testUrl = baseUrl + entry.path();
                try {
                    HttpRequest req = HttpRequest.newBuilder()
                            .uri(URI.create(testUrl))
                            .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ATTT-DirScanner/1.0")
                            .timeout(Duration.ofSeconds(6))
                            .method("GET", HttpRequest.BodyPublishers.noBody())
                            .build();

                    HttpResponse<Void> resp = client.send(req, HttpResponse.BodyHandlers.discarding());
                    int status = resp.statusCode();

                    // Only consider 200, 204, 301, 302, 307, 401, 403 as notable paths
                    if (status == 200 || status == 204 || (status >= 300 && status <= 308) || status == 401 || status == 403) {
                        String redirect = resp.headers().firstValue("Location").orElse(null);
                        long length = resp.headers().firstValueAsLong("Content-Length").orElse(-1L);

                        discovered.add(WebDirResultDto.builder()
                                .path(entry.path())
                                .url(testUrl)
                                .statusCode(status)
                                .statusText(getStatusText(status))
                                .contentLength(length)
                                .redirectLocation(redirect)
                                .isSensitive(entry.isSensitive())
                                .category(entry.category())
                                .riskLevel(entry.riskLevel())
                                .build());
                    }
                } catch (Exception ignored) {
                    // Timeout or connection error for specific path
                }
            }, executor);

            futures.add(future);
        }

        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).get(25, TimeUnit.SECONDS);
        } catch (Exception e) {
            log.debug("Directory scan timed out or was interrupted: {}", e.getMessage());
        } finally {
            executor.shutdown();
        }

        discovered.sort(Comparator.comparingInt(WebDirResultDto::getStatusCode));

        for (WebDirResultDto item : discovered) {
            if (item.isSensitive() && item.getStatusCode() == 200) {
                sensitiveCount++;
            }
        }

        long duration = System.currentTimeMillis() - startTime;

        return WebDirectoryScanResult.builder()
                .targetUrl(baseUrl)
                .totalPathsTested(DEFAULT_WORDLIST.size())
                .discoveredPaths(discovered)
                .sensitiveCount(sensitiveCount)
                .durationMs(duration)
                .success(true)
                .build();
    }

    private String cleanBaseUrl(String input) {
        if (input == null) return "http://localhost";
        String trimmed = input.trim();
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            trimmed = "http://" + trimmed;
        }
        if (trimmed.endsWith("/")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private String getStatusText(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 301 -> "Moved Permanently";
            case 302 -> "Found / Redirect";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 500 -> "Internal Server Error";
            default -> "HTTP " + code;
        };
    }
}
