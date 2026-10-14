package com.example.backend.modules.recon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@Slf4j
public class WhoisService {

    private static final String DEFAULT_WHOIS_SERVER = "whois.iana.org";
    private static final int WHOIS_PORT = 43;
    private static final int TIMEOUT_MS = 5000;

    public WhoisResult queryWhois(String domainOrIp) {
        String cleanTarget = DnsReconService.extractCleanDomain(domainOrIp);

        if (cleanTarget.equals("localhost") || cleanTarget.equals("127.0.0.1") || cleanTarget.equals("::1") 
                || cleanTarget.startsWith("192.168.") || cleanTarget.startsWith("10.") || cleanTarget.startsWith("172.")) {
            return WhoisResult.builder()
                    .query(cleanTarget)
                    .registrar("Local Loopback / Private Network")
                    .creationDate("N/A")
                    .expiryDate("N/A")
                    .updatedDate("N/A")
                    .organization("Localhost Private Host")
                    .country("VN / Local")
                    .nameServers(List.of("127.0.0.1"))
                    .rawWhois("Localhost / Private Network - No external WHOIS record.")
                    .success(true)
                    .build();
        }

        try {
            // 1. Query IANA first to find the authoritative whois server
            String ianaResponse = querySocket(DEFAULT_WHOIS_SERVER, cleanTarget);
            String whoisServer = extractWhoisServer(ianaResponse);

            if (whoisServer == null || whoisServer.isEmpty()) {
                // Fallback heuristic based on TLD
                if (cleanTarget.endsWith(".com") || cleanTarget.endsWith(".net")) {
                    whoisServer = "whois.verisign-grs.com";
                } else if (cleanTarget.endsWith(".org")) {
                    whoisServer = "whois.pir.org";
                } else if (cleanTarget.endsWith(".vn")) {
                    whoisServer = "whois.vnnic.vn";
                } else {
                    whoisServer = "whois.internic.net";
                }
            }

            // 2. Query Authoritative WHOIS Server
            String fullResponse = querySocket(whoisServer, cleanTarget);
            if (fullResponse == null || fullResponse.trim().isEmpty()) {
                fullResponse = ianaResponse;
            }

            // 3. Parse key attributes
            String registrar = extractPattern(fullResponse, "(?i)Registrar:\\s*(.+)");
            String creationDate = extractPattern(fullResponse, "(?i)(?:Creation Date|Created|Registered On):\\s*(.+)");
            String expiryDate = extractPattern(fullResponse, "(?i)(?:Registry Expiry Date|Expiration Date|Expires on):\\s*(.+)");
            String updatedDate = extractPattern(fullResponse, "(?i)(?:Updated Date|Last Updated On):\\s*(.+)");
            String organization = extractPattern(fullResponse, "(?i)(?:Registrant Organization|Org-Name|Tech Organization):\\s*(.+)");
            String country = extractPattern(fullResponse, "(?i)(?:Registrant Country|Country):\\s*(.+)");

            List<String> nameServers = extractAllPatterns(fullResponse, "(?i)Name Server:\\s*(\\S+)");

            return WhoisResult.builder()
                    .query(cleanTarget)
                    .registrar(registrar != null ? registrar : "N/A")
                    .creationDate(creationDate != null ? creationDate : "N/A")
                    .expiryDate(expiryDate != null ? expiryDate : "N/A")
                    .updatedDate(updatedDate != null ? updatedDate : "N/A")
                    .organization(organization != null ? organization : "N/A")
                    .country(country != null ? country : "N/A")
                    .nameServers(nameServers)
                    .rawWhois(fullResponse.length() > 4000 ? fullResponse.substring(0, 4000) + "... [Đã rút gọn]" : fullResponse)
                    .success(true)
                    .build();

        } catch (Exception e) {
            log.warn("WHOIS query failed for {}: {}", cleanTarget, e.getMessage());
            return WhoisResult.builder()
                    .query(cleanTarget)
                    .success(false)
                    .errorMessage("Lỗi khi tra cứu WHOIS: " + e.getMessage())
                    .build();
        }
    }

    private String querySocket(String server, String query) throws Exception {
        try (Socket socket = new Socket(server, WHOIS_PORT)) {
            socket.setSoTimeout(TIMEOUT_MS);
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            out.println(query);

            StringBuilder response = new StringBuilder();
            String line;
            while ((line = in.readLine()) != null) {
                response.append(line).append("\n");
            }
            return response.toString();
        }
    }

    private String extractWhoisServer(String response) {
        Pattern pattern = Pattern.compile("(?i)(?:refer|whois):\\s*([a-zA-Z0-9.-]+)");
        Matcher matcher = pattern.matcher(response);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }

    private String extractPattern(String text, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(text);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }

    private List<String> extractAllPatterns(String text, String regex) {
        List<String> results = new ArrayList<>();
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(text);
        while (matcher.find()) {
            String ns = matcher.group(1).trim().toLowerCase();
            if (!results.contains(ns)) {
                results.add(ns);
            }
        }
        return results;
    }
}
