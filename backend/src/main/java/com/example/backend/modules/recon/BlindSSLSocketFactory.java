package com.example.backend.modules.recon;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.cert.X509Certificate;

public class BlindSSLSocketFactory extends SocketFactory {
    private static SocketFactory defaultFactory;

    static {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[]{new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(X509Certificate[] certs, String authType) {}
            }}, new java.security.SecureRandom());
            defaultFactory = sslContext.getSocketFactory();
        } catch (Exception e) {
            defaultFactory = SSLSocketFactory.getDefault();
        }
    }

    public static SocketFactory getDefault() {
        return new BlindSSLSocketFactory();
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        return defaultFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort) throws IOException {
        return defaultFactory.createSocket(host, port, localHost, localPort);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return defaultFactory.createSocket(host, port);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort) throws IOException {
        return defaultFactory.createSocket(address, port, localAddress, localPort);
    }
}
