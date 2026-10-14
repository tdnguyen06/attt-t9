package com.example.backend;

import com.example.backend.modules.scan.NmapScanResult;
import com.example.backend.modules.scan.NmapXmlParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class NmapXmlParserTest {

    private final NmapXmlParser parser = new NmapXmlParser();

    @Test
    void testParseValidNmapXml() {
        String xml = """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE nmaprun>
                <nmaprun scanner="nmap" args="nmap -sV -oX - scanme.nmap.org" start="1700000000">
                  <host>
                    <status state="up"/>
                    <address addr="45.33.32.156" addrtype="ipv4"/>
                    <hostnames>
                      <hostname name="scanme.nmap.org" type="user"/>
                    </hostnames>
                    <ports>
                      <port protocol="tcp" portid="80">
                        <state state="open"/>
                        <service name="http" product="Apache httpd" version="2.4.7"/>
                      </port>
                      <port protocol="tcp" portid="22">
                        <state state="open"/>
                        <service name="ssh" product="OpenSSH" version="6.6.1p1"/>
                      </port>
                    </ports>
                  </host>
                  <runstats>
                    <hosts up="1" down="0" total="1"/>
                  </runstats>
                </nmaprun>
                """;

        NmapScanResult result = parser.parse(xml);
        assertNotNull(result);
        assertEquals(1, result.totalHostsUp());
        assertEquals(2, result.totalOpenPorts());
        assertEquals(1, result.hosts().size());

        var host = result.hosts().get(0);
        assertEquals("45.33.32.156", host.ipAddress());
        assertEquals("scanme.nmap.org", host.hostName());
        assertEquals(2, host.ports().size());

        var p80 = host.ports().get(0);
        assertEquals(80, p80.portId());
        assertEquals("http", p80.serviceName());
        assertEquals("Apache httpd", p80.product());
    }
}
