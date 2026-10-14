package com.example.backend.modules.scan;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

@Component
@Slf4j
public class NmapXmlParser {

    /**
     * Phân tích an toàn XML output của Nmap (Chống XXE Attack)
     */
    public NmapScanResult parse(String xmlContent) {
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            return new NmapScanResult("nmap", "", "", "", List.of(), 0, 0);
        }

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // Thiết lập phòng chống XXE Injection an toàn với Nmap XML (có DOCTYPE)
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new InputSource(new StringReader(xmlContent)));
            doc.getDocumentElement().normalize();

            Element root = doc.getDocumentElement();
            String scanner = root.getAttribute("scanner");
            String args = root.getAttribute("args");
            String version = root.getAttribute("version");
            String startStr = root.getAttribute("startstr");

            List<HostResult> hosts = new ArrayList<>();
            NodeList hostNodes = doc.getElementsByTagName("host");

            int totalOpenPorts = 0;
            int totalHostsUp = 0;

            for (int i = 0; i < hostNodes.getLength(); i++) {
                Element hostEl = (Element) hostNodes.item(i);

                // Check status
                String state = "unknown";
                NodeList statusNodes = hostEl.getElementsByTagName("status");
                if (statusNodes.getLength() > 0) {
                    state = ((Element) statusNodes.item(0)).getAttribute("state");
                }

                if ("up".equalsIgnoreCase(state)) {
                    totalHostsUp++;
                }

                // IP Address
                String ipAddress = "";
                NodeList addrNodes = hostEl.getElementsByTagName("address");
                for (int a = 0; a < addrNodes.getLength(); a++) {
                    Element addrEl = (Element) addrNodes.item(a);
                    if ("ipv4".equals(addrEl.getAttribute("addrtype")) || "ipv6".equals(addrEl.getAttribute("addrtype"))) {
                        ipAddress = addrEl.getAttribute("addr");
                        break;
                    }
                }

                // Hostname
                String hostname = "";
                NodeList hnNodes = hostEl.getElementsByTagName("hostname");
                if (hnNodes.getLength() > 0) {
                    hostname = ((Element) hnNodes.item(0)).getAttribute("name");
                }

                // Ports
                List<PortResult> ports = new ArrayList<>();
                NodeList portNodes = hostEl.getElementsByTagName("port");
                for (int p = 0; p < portNodes.getLength(); p++) {
                    Element portEl = (Element) portNodes.item(p);
                    int portId = Integer.parseInt(portEl.getAttribute("portid"));
                    String protocol = portEl.getAttribute("protocol");

                    String portState = "";
                    NodeList pStateNodes = portEl.getElementsByTagName("state");
                    if (pStateNodes.getLength() > 0) {
                        portState = ((Element) pStateNodes.item(0)).getAttribute("state");
                    }

                    if ("open".equalsIgnoreCase(portState)) {
                        totalOpenPorts++;
                    }

                    String serviceName = "";
                    String product = "";
                    String serviceVersion = "";
                    String extraInfo = "";

                    NodeList sNodes = portEl.getElementsByTagName("service");
                    if (sNodes.getLength() > 0) {
                        Element sEl = (Element) sNodes.item(0);
                        serviceName = sEl.getAttribute("name");
                        product = sEl.getAttribute("product");
                        serviceVersion = sEl.getAttribute("version");
                        extraInfo = sEl.getAttribute("extrainfo");
                    }

                    List<ScriptResult> scripts = new ArrayList<>();
                    NodeList scriptNodes = portEl.getElementsByTagName("script");
                    for (int s = 0; s < scriptNodes.getLength(); s++) {
                        Element scriptEl = (Element) scriptNodes.item(s);
                        scripts.add(new ScriptResult(
                                scriptEl.getAttribute("id"),
                                scriptEl.getAttribute("output")
                        ));
                    }

                    ports.add(new PortResult(portId, protocol, portState, serviceName, product, serviceVersion, extraInfo, scripts));
                }

                hosts.add(new HostResult(ipAddress, hostname, state, "", ports));
            }

            return new NmapScanResult(scanner, args, version, startStr, hosts, totalHostsUp, totalOpenPorts);
        } catch (Exception e) {
            log.error("Lỗi khi phân tích Nmap XML: {}", e.getMessage());
            return new NmapScanResult("nmap", "", "", "", List.of(), 0, 0);
        }
    }
}
