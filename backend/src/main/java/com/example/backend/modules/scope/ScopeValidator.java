package com.example.backend.modules.scope;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

@Component
public class ScopeValidator {

    public void validateTarget(String type, String target) {
        if (target == null || target.trim().isEmpty()) {
            throw new IllegalArgumentException("Mục tiêu (target) không được để trống");
        }

        String cleaned = target.trim();

        // Tự động nhận diện URL nếu có http/https
        if (cleaned.startsWith("http://") || cleaned.startsWith("https://")) {
            validateUrl(cleaned);
            return;
        }

        if ("SERVER".equalsIgnoreCase(type)) {
            validateIpOrCidr(cleaned);
        } else {
            validateUrl(cleaned);
        }
    }

    public void validateIpOrCidr(String target) {
        String cleaned = target.trim();
        if (cleaned.contains("/")) {
            String[] parts = cleaned.split("/");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Định dạng CIDR không hợp lệ (Ví dụ đúng: 192.168.1.0/24)");
            }

            validateIp(parts[0]);

            try {
                int prefix = Integer.parseInt(parts[1]);
                if (prefix < 0 || prefix > 32) {
                    throw new IllegalArgumentException("CIDR prefix phải từ 0 đến 32");
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("CIDR prefix không hợp lệ");
            }
            return;
        }

        validateIp(cleaned);
    }

    public void validateIp(String ipStr) {
        if (ipStr == null || ipStr.trim().isEmpty()) {
            throw new IllegalArgumentException("Địa chỉ IP hoặc Hostname không được để trống");
        }

        String host = ipStr.trim();
        // Bóc tách nếu có protocol
        if (host.contains("://")) {
            host = host.substring(host.indexOf("://") + 3);
        }
        // Bóc tách nếu có path
        if (host.contains("/")) {
            host = host.substring(0, host.indexOf('/'));
        }
        // Bóc tách nếu có cổng (ví dụ: bore.pub:9845 hoặc 127.0.0.1:8888)
        if (host.contains(":")) {
            host = host.substring(0, host.indexOf(':'));
        }

        if (host.equalsIgnoreCase("localhost") || host.equals("127.0.0.1") || host.equals("::1")) {
            return;
        }

        try {
            InetAddress.getByName(host);
        } catch (UnknownHostException e) {
            // Cho phép các hostname/domain nội bộ trong môi trường lab hoặc public tunnel
            if (host.matches("^[a-zA-Z0-9.-]+$") && host.length() >= 1) {
                return;
            }
            throw new IllegalArgumentException("Địa chỉ IP hoặc Hostname không hợp lệ: " + ipStr);
        }
    }

    public void validateUrl(String urlStr) {
        String target = urlStr.trim();
        // Tự động hỗ trợ nếu người dùng nhập domain không kèm http/https
        if (!target.contains("://")) {
            target = "http://" + target;
        }

        try {
            URI uri = URI.create(target);
            String scheme = uri.getScheme();

            if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
                throw new IllegalArgumentException("URL phải sử dụng giao thức http hoặc https");
            }

            if (uri.getHost() == null || uri.getHost().trim().isEmpty()) {
                throw new IllegalArgumentException("URL không có tên miền/host hợp lệ: " + urlStr);
            }
        } catch (Exception e) {
            if (e instanceof IllegalArgumentException) {
                throw e;
            }
            throw new IllegalArgumentException("Định dạng URL không hợp lệ: " + urlStr);
        }
    }

    /**
     * Kiểm tra xem IP mục tiêu có nằm trong CIDR subnet hay không
     */
    public boolean isIpInCidr(String ipAddress, String cidr) {
        try {
            if (!cidr.contains("/")) {
                return ipAddress.trim().equalsIgnoreCase(cidr.trim());
            }

            String[] parts = cidr.split("/");
            InetAddress targetAddr = InetAddress.getByName(ipAddress.trim());
            InetAddress subnetAddr = InetAddress.getByName(parts[0].trim());
            int prefix = Integer.parseInt(parts[1].trim());

            byte[] targetBytes = targetAddr.getAddress();
            byte[] subnetBytes = subnetAddr.getAddress();

            if (targetBytes.length != subnetBytes.length) {
                return false;
            }

            int fullBytes = prefix / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (targetBytes[i] != subnetBytes[i]) {
                    return false;
                }
            }

            int remainingBits = prefix % 8;
            if (remainingBits > 0) {
                int mask = (0xFF << (8 - remainingBits)) & 0xFF;
                if ((targetBytes[fullBytes] & mask) != (subnetBytes[fullBytes] & mask)) {
                    return false;
                }
            }

            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
