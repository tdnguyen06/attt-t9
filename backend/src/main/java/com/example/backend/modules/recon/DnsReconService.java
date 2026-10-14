package com.example.backend.modules.recon;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.net.InetAddress;
import java.util.*;

@Service
@Slf4j
public class DnsReconService {

    private static final String[] RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"};

    public DnsReconResult performDnsRecon(String hostOrDomain) {
        String cleanDomain = extractCleanDomain(hostOrDomain);
        List<String> resolvedIps = new ArrayList<>();
        List<DnsRecordDto> records = new ArrayList<>();

        if (cleanDomain.equals("localhost") || cleanDomain.equals("127.0.0.1") || cleanDomain.equals("::1")
                || cleanDomain.startsWith("192.168.") || cleanDomain.startsWith("10.") || cleanDomain.startsWith("172.")) {
            resolvedIps.add("127.0.0.1");
            records.add(DnsRecordDto.builder().type("A").value("127.0.0.1").raw("localhost. IN A 127.0.0.1").build());
            return DnsReconResult.builder()
                    .domain(cleanDomain)
                    .resolvedIps(resolvedIps)
                    .records(records)
                    .summary("Domain " + cleanDomain + " phân giải nội bộ: 127.0.0.1 (Loopback / Private Host)")
                    .success(true)
                    .build();
        }

        try {
            // 1. Resolve IP addresses
            InetAddress[] addresses = InetAddress.getAllByName(cleanDomain);
            for (InetAddress addr : addresses) {
                resolvedIps.add(addr.getHostAddress());
            }

            // 2. Query JNDI DNS records
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", "dns://8.8.8.8"); // Use public DNS resolver

            DirContext dirContext = new InitialDirContext(env);

            for (String type : RECORD_TYPES) {
                try {
                    Attributes attrs = dirContext.getAttributes(cleanDomain, new String[]{type});
                    Attribute attr = attrs.get(type);
                    if (attr != null) {
                        NamingEnumeration<?> en = attr.getAll();
                        while (en.hasMore()) {
                            Object val = en.next();
                            records.add(DnsRecordDto.builder()
                                    .type(type)
                                    .value(val != null ? val.toString().trim() : "")
                                    .raw(val != null ? val.toString() : "")
                                    .build());
                        }
                    }
                } catch (Exception ignored) {
                    // Specific record type might not exist
                }
            }

            String summary = String.format("Domain %s phân giải thành %d IP(s), thu thập được %d bản ghi DNS.",
                    cleanDomain, resolvedIps.size(), records.size());

            return DnsReconResult.builder()
                    .domain(cleanDomain)
                    .resolvedIps(resolvedIps)
                    .records(records)
                    .summary(summary)
                    .success(true)
                    .build();

        } catch (Exception e) {
            log.warn("Lỗi khi thực hiện DNS recon cho {}: {}", cleanDomain, e.getMessage());
            return DnsReconResult.builder()
                    .domain(cleanDomain)
                    .resolvedIps(resolvedIps)
                    .records(records)
                    .success(false)
                    .errorMessage("Không thể phân giải DNS: " + e.getMessage())
                    .build();
        }
    }

    public static String extractCleanDomain(String input) {
        if (input == null) return "";
        String domain = input.trim();
        if (domain.startsWith("http://")) domain = domain.substring(7);
        if (domain.startsWith("https://")) domain = domain.substring(8);
        int slashIdx = domain.indexOf('/');
        if (slashIdx != -1) domain = domain.substring(0, slashIdx);
        int colonIdx = domain.indexOf(':');
        if (colonIdx != -1) domain = domain.substring(0, colonIdx);
        return domain;
    }
}
