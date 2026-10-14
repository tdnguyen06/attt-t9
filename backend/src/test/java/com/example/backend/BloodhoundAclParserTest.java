package com.example.backend;

import com.example.backend.modules.recon.BloodhoundAdCollectorService;
import com.example.backend.modules.recon.BloodhoundFilterService;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.junit.jupiter.api.Assertions.*;

public class BloodhoundAclParserTest {

    @Test
    void testSidBytesToString() {
        // S-1-5-21-1000-2000-3000-1105
        ByteBuffer bb = ByteBuffer.allocate(28).order(ByteOrder.LITTLE_ENDIAN);
        bb.put((byte) 1); // revision
        bb.put((byte) 5); // sub-authority count: 5
        // 6 bytes authority: 5 (NT Authority)
        bb.put(new byte[]{0, 0, 0, 0, 0, 5});
        bb.putInt(21);
        bb.putInt(1000);
        bb.putInt(2000);
        bb.putInt(3000);
        bb.putInt(1105);

        String sid = BloodhoundAdCollectorService.sidBytesToString(bb.array());
        assertEquals("S-1-5-21-1000-2000-3000-1105", sid);
    }

    @Test
    void testDetermineRightName() {
        BloodhoundAdCollectorService.RawAce ace1 = new BloodhoundAdCollectorService.RawAce();
        ace1.mask = 0x10000000; // GENERIC_ALL
        assertEquals("GenericAll", BloodhoundAdCollectorService.determineRightName(ace1));

        BloodhoundAdCollectorService.RawAce ace2 = new BloodhoundAdCollectorService.RawAce();
        ace2.mask = 0x00040000; // WRITE_DAC
        assertEquals("WriteDacl", BloodhoundAdCollectorService.determineRightName(ace2));

        BloodhoundAdCollectorService.RawAce ace3 = new BloodhoundAdCollectorService.RawAce();
        ace3.objectTypeGuid = "00299570-246d-11d0-a765-00a0c911e510"; // ForceChangePassword
        assertEquals("ForceChangePassword", BloodhoundAdCollectorService.determineRightName(ace3));
    }

    @Test
    void testParseSecurityDescriptor() {
        // Tạo Security Descriptor nhị phân giả lập (MS-DTYP) với 1 ACE
        // Header: Revision(1), Sbz1(0), Control(0x0004 - SE_DACL_PRESENT), OffsetOwner(0), OffsetGroup(0), OffsetSacl(0), OffsetDacl(20)
        int daclOffset = 20;
        int aceSize = 8 + 28; // 8 bytes header/mask + 28 bytes SID
        int aclSize = 8 + aceSize;
        ByteBuffer bb = ByteBuffer.allocate(daclOffset + aclSize).order(ByteOrder.LITTLE_ENDIAN);
        
        // Security Descriptor Header (20 bytes)
        bb.put((byte) 1); // Revision
        bb.put((byte) 0); // Sbz1
        bb.putShort((short) 0x0004); // Control: SE_DACL_PRESENT
        bb.putInt(0); // OffsetOwner
        bb.putInt(0); // OffsetGroup
        bb.putInt(0); // OffsetSacl
        bb.putInt(daclOffset); // OffsetDacl

        // ACL Header (8 bytes at offset 20)
        bb.put((byte) 2); // AclRevision
        bb.put((byte) 0); // Sbz1
        bb.putShort((short) aclSize); // AclSize
        bb.putShort((short) 1); // AceCount: 1
        bb.putShort((short) 0); // Sbz2

        // ACE 0: ACCESS_ALLOWED_ACE (0x00)
        bb.put((byte) 0); // AceType: 0x00
        bb.put((byte) 0); // AceFlags
        bb.putShort((short) aceSize); // AceSize
        bb.putInt(0x10000000); // Mask: GENERIC_ALL

        // SID: S-1-5-21-1000-2000-3000-1105
        bb.put((byte) 1);
        bb.put((byte) 5);
        bb.put(new byte[]{0, 0, 0, 0, 0, 5});
        bb.putInt(21);
        bb.putInt(1000);
        bb.putInt(2000);
        bb.putInt(3000);
        bb.putInt(1105);

        var rawAces = BloodhoundAdCollectorService.parseSecurityDescriptor(bb.array());
        assertEquals(1, rawAces.size());
        assertEquals("S-1-5-21-1000-2000-3000-1105", rawAces.get(0).trusteeSid);
        assertEquals(0x10000000, rawAces.get(0).mask);
        assertEquals("GenericAll", BloodhoundAdCollectorService.determineRightName(rawAces.get(0)));
    }

    @Test
    void testFilterServiceDetectsAttackerPrivEsc() {
        String json = """
        {
          "data": [
            {
              "Properties": {
                "name": "ADMINISTRATOR@VNCERT.VN",
                "enabled": true,
                "admincount": true
              },
              "Aces": [
                {
                  "PrincipalName": "ATTACKER@VNCERT.VN",
                  "PrincipalType": "User",
                  "RightName": "GenericAll",
                  "TargetName": "ADMINISTRATOR@VNCERT.VN"
                }
              ]
            }
          ],
          "meta": {
            "domain": "vncert.vn"
          }
        }
        """;

        BloodhoundFilterService filterService = new BloodhoundFilterService();
        var summary = filterService.filterAndSummarize(json);
        summary.setAuthenticatedUser("attacker");

        assertEquals(1, summary.getCriticalRiskCount());
        assertFalse(summary.getHighRiskFindings().isEmpty());
        var finding = summary.getHighRiskFindings().get(0);
        assertEquals("ATTACKER@VNCERT.VN", finding.getSourcePrincipal());
        assertEquals("ADMINISTRATOR@VNCERT.VN", finding.getTargetObject());
        assertEquals("GenericAll", finding.getRelationshipType());
        assertEquals("CRITICAL", finding.getRiskLevel());

        String compactPrompt = filterService.buildCompactPromptSummary(summary);
        assertTrue(compactPrompt.contains("[CRITICAL] ATTACKER@VNCERT.VN -> (GenericAll) -> ADMINISTRATOR@VNCERT.VN"));
        assertTrue(compactPrompt.contains("Tài khoản người kiểm thử đang nắm giữ: attacker"));
    }

    @Test
    void testFilterServiceDetectsAttackerPrivEscToAdminUser() {
        String json = """
        {
          "data": [
            {
              "Properties": {
                "name": "ADMIN@VNCERT.VN",
                "enabled": true,
                "admincount": true
              },
              "Aces": [
                {
                  "PrincipalName": "ATTACKER@VNCERT.VN",
                  "PrincipalType": "User",
                  "RightName": "GenericAll",
                  "TargetName": "ADMIN@VNCERT.VN"
                }
              ]
            }
          ],
          "meta": {
            "domain": "vncert.vn"
          }
        }
        """;

        BloodhoundFilterService filterService = new BloodhoundFilterService();
        var summary = filterService.filterAndSummarize(json);
        summary.setAuthenticatedUser("attacker");

        assertEquals(1, summary.getCriticalRiskCount());
        assertFalse(summary.getHighRiskFindings().isEmpty());
        var finding = summary.getHighRiskFindings().get(0);
        assertEquals("ATTACKER@VNCERT.VN", finding.getSourcePrincipal());
        assertEquals("ADMIN@VNCERT.VN", finding.getTargetObject());
        assertEquals("GenericAll", finding.getRelationshipType());
        assertEquals("CRITICAL", finding.getRiskLevel());

        String compactPrompt = filterService.buildCompactPromptSummary(summary);
        assertTrue(compactPrompt.contains("[CRITICAL] ATTACKER@VNCERT.VN -> (GenericAll) -> ADMIN@VNCERT.VN"));
    }
}
