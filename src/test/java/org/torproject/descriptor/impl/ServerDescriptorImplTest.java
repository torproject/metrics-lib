/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.BandwidthHistory;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ServerDescriptor;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeSet;

/* Test parsing of relay server descriptors. */
public class ServerDescriptorImplTest {

  /* Helper class to build a descriptor based on default data and
   * modifications requested by test methods. */
  private static class DescriptorBuilder {

    private String routerLine = "router saberrider2008 94.134.192.243 "
        + "9001 0 0";

    private static ServerDescriptor createWithRouterLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.routerLine = line;
      return db.buildDescriptor(true);
    }

    private String bandwidthLine = "bandwidth 51200 51200 53470";

    private static ServerDescriptor createWithBandwidthLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.bandwidthLine = line;
      return db.buildDescriptor(true);
    }

    private String platformLine = "platform Tor 0.2.2.35 "
        + "(git-b04388f9e7546a9f) on Linux i686";

    private static ServerDescriptor createWithPlatformLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.platformLine = line;
      return db.buildDescriptor(true);
    }

    private String publishedLine = "published 2012-01-01 04:03:19";

    private static ServerDescriptor createWithPublishedLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.publishedLine = line;
      return db.buildDescriptor(true);
    }

    private String fingerprintLine = "opt fingerprint D873 3048 FC8E "
        + "C910 2466 AD8F 3098 622B F1BF 71FD";

    private static ServerDescriptor createWithFingerprintLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.fingerprintLine = line;
      return db.buildDescriptor(true);
    }

    private String hibernatingLine = null;

    private static ServerDescriptor createWithHibernatingLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.hibernatingLine = line;
      return db.buildDescriptor(true);
    }

    private String uptimeLine = "uptime 48";

    private static ServerDescriptor createWithUptimeLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.uptimeLine = line;
      return db.buildDescriptor(true);
    }

    private String onionKeyLines = "onion-key\n"
        + "-----BEGIN RSA PUBLIC KEY-----\n"
        + "MIGJAoGBAKM+iiHhO6eHsvd6Xjws9z9EQB1V/Bpuy5ciGJ1U4V9SeiKooSo5Bp"
        + "PL\no3XT+6PIgzl3R6uycjS3Ejk47vLEJdcVTm/VG6E0ppu3olIynCI4QryfCE"
        + "uC3cTF\n9wE4WXY4nX7w0RTN18UVLxrt1A9PP0cobFNiPs9rzJCbKFfacOkpAg"
        + "MBAAE=\n"
        + "-----END RSA PUBLIC KEY-----";

    private static ServerDescriptor createWithOnionKeyLines(
        String lines) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.onionKeyLines = lines;
      return db.buildDescriptor(true);
    }

    private String signingKeyLines = "signing-key\n"
        + "-----BEGIN RSA PUBLIC KEY-----\n"
        + "MIGJAoGBALMm3r3QDh482Ewe6Ub9wvRIfmEkoNX6q5cEAtQRNHSDcNx41gjELb"
        + "cl\nEniVMParBYACKfOxkS+mTTnIRDKVNEJTsDOwryNrc4X9JnPc/nn6ymYPiN"
        + "DhUROG\n8URDIhQoixcUeyyrVB8sxliSstKimulGnB7xpjYOlO8JKaHLNL4TAg"
        + "MBAAE=\n"
        + "-----END RSA PUBLIC KEY-----";

    private static ServerDescriptor createWithSigningKeyLines(
        String lines) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.signingKeyLines = lines;
      return db.buildDescriptor(true);
    }

    private String onionKeyCrosscertLines = null;

    private static ServerDescriptor createWithOnionKeyCrosscertLines(
        String lines) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.onionKeyCrosscertLines = lines;
      return db.buildDescriptor(true);
    }

    private String ntorOnionKeyCrosscertLines = null;

    private static ServerDescriptor createWithNtorOnionKeyCrosscertLines(
        String lines) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.ntorOnionKeyCrosscertLines = lines;
      return db.buildDescriptor(true);
    }

    private String exitPolicyLines = "reject *:*";

    private static ServerDescriptor createWithExitPolicyLines(
        String lines) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.exitPolicyLines = lines;
      return db.buildDescriptor(true);
    }

    private String contactLine = "contact Random Person <nobody AT "
        + "example dot com>";

    private static ServerDescriptor createWithContactLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.contactLine = line;
      return db.buildDescriptor(true);
    }

    private String familyLine = null;

    private static ServerDescriptor createWithFamilyLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.familyLine = line;
      return db.buildDescriptor(true);
    }

    private String readHistoryLine = null;

    private static ServerDescriptor createWithReadHistoryLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.readHistoryLine = line;
      return db.buildDescriptor(true);
    }

    private String writeHistoryLine = null;

    private static ServerDescriptor createWithWriteHistoryLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.writeHistoryLine = line;
      return db.buildDescriptor(true);
    }

    private String eventdnsLine = null;

    private static ServerDescriptor createWithEventdnsLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.eventdnsLine = line;
      return db.buildDescriptor(true);
    }

    private String cachesExtraInfoLine = null;

    private static ServerDescriptor createWithCachesExtraInfoLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.cachesExtraInfoLine = line;
      return db.buildDescriptor(true);
    }

    private String extraInfoDigestLine = "opt extra-info-digest "
        + "1469D1550738A25B1E7B47CDDBCD7B2899F51B74";

    private static ServerDescriptor createWithExtraInfoDigestLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.extraInfoDigestLine = line;
      return db.buildDescriptor(true);
    }

    private String hiddenServiceDirLine = "opt hidden-service-dir";

    private static ServerDescriptor createWithHiddenServiceDirLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.hiddenServiceDirLine = line;
      return db.buildDescriptor(true);
    }

    private String protocolsLine = null;

    private static ServerDescriptor createWithProtocolsLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.protocolsLine = line;
      return db.buildDescriptor(true);
    }

    private String protoLine = "proto Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 "
        + "HSIntro=3 HSRend=1-2 Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";

    private static ServerDescriptor createWithProtoLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.protoLine = line;
      return db.buildDescriptor(true);
    }

    private String allowSingleHopExitsLine = null;

    private static ServerDescriptor
        createWithAllowSingleHopExitsLine(String line)
        throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.allowSingleHopExitsLine = line;
      return db.buildDescriptor(true);
    }

    private String ipv6PolicyLine = null;

    private static ServerDescriptor createWithIpv6PolicyLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.ipv6PolicyLine = line;
      return db.buildDescriptor(true);
    }

    private String ntorOnionKeyLine = null;

    private static ServerDescriptor createWithNtorOnionKeyLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.ntorOnionKeyLine = line;
      return db.buildDescriptor(true);
    }

    private String tunnelledDirServerLine = null;

    private static ServerDescriptor createWithTunnelledDirServerLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.tunnelledDirServerLine = line;
      return db.buildDescriptor(true);
    }

    private String routerSignatureLines = "router-signature\n"
        + "-----BEGIN SIGNATURE-----\n"
        + "o4j+kH8UQfjBwepUnr99v0ebN8RpzHJ/lqYsTojXHy9kMr1RNI9IDeSzA7PSqT"
        + "uV\n4PL8QsGtlfwthtIoZpB2srZeyN/mcpA9fa1JXUrt/UN9K/+32Cyaad7h0n"
        + "HE6Xfb\njqpXDpnBpvk4zjmzjjKYnIsUWTnADmu0fo3xTRqXi7g=\n"
        + "-----END SIGNATURE-----";

    private static ServerDescriptor createWithRouterSignatureLines(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.routerSignatureLines = line;
      return db.buildDescriptor(true);
    }

    private String unrecognizedLine = null;

    private static ServerDescriptor createWithUnrecognizedLine(
        String line, boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.unrecognizedLine = line;
      return db.buildDescriptor(failUnrecognizedDescriptorLines);
    }

    private byte[] nonAsciiLineBytes = null;

    private static ServerDescriptor createWithNonAsciiLineBytes(
        byte[] lineBytes, boolean failUnrecognizedDescriptorLines)
            throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.nonAsciiLineBytes = lineBytes;
      return db.buildDescriptor(failUnrecognizedDescriptorLines);
    }

    private String identityEd25519Lines = null;

    private String masterKeyEd25519Line = null;

    private String routerSigEd25519Line = null;

    private static ServerDescriptor createWithEd25519Lines(
        String identityEd25519Lines, String masterKeyEd25519Line,
        String routerSigEd25519Line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.identityEd25519Lines = identityEd25519Lines;
      db.masterKeyEd25519Line = masterKeyEd25519Line;
      db.routerSigEd25519Line = routerSigEd25519Line;
      return db.buildDescriptor(true);
    }

    private byte[] buildDescriptorBytes() {
      StringBuilder sb = new StringBuilder();
      if (this.routerLine != null) {
        sb.append(this.routerLine).append("\n");
      }
      if (this.identityEd25519Lines != null) {
        sb.append(this.identityEd25519Lines).append("\n");
      }
      if (this.masterKeyEd25519Line != null) {
        sb.append(this.masterKeyEd25519Line).append("\n");
      }
      if (this.bandwidthLine != null) {
        sb.append(this.bandwidthLine).append("\n");
      }
      if (this.platformLine != null) {
        sb.append(this.platformLine).append("\n");
      }
      if (this.publishedLine != null) {
        sb.append(this.publishedLine).append("\n");
      }
      if (this.fingerprintLine != null) {
        sb.append(this.fingerprintLine).append("\n");
      }
      if (this.hibernatingLine != null) {
        sb.append(this.hibernatingLine).append("\n");
      }
      if (this.uptimeLine != null) {
        sb.append(this.uptimeLine).append("\n");
      }
      if (this.onionKeyLines != null) {
        sb.append(this.onionKeyLines).append("\n");
      }
      if (this.signingKeyLines != null) {
        sb.append(this.signingKeyLines).append("\n");
      }
      if (this.onionKeyCrosscertLines != null) {
        sb.append(this.onionKeyCrosscertLines).append("\n");
      }
      if (this.ntorOnionKeyCrosscertLines != null) {
        sb.append(this.ntorOnionKeyCrosscertLines).append("\n");
      }
      if (this.exitPolicyLines != null) {
        sb.append(this.exitPolicyLines).append("\n");
      }
      if (this.contactLine != null) {
        sb.append(this.contactLine).append("\n");
      }
      if (this.familyLine != null) {
        sb.append(this.familyLine).append("\n");
      }
      if (this.readHistoryLine != null) {
        sb.append(this.readHistoryLine).append("\n");
      }
      if (this.writeHistoryLine != null) {
        sb.append(this.writeHistoryLine).append("\n");
      }
      if (this.eventdnsLine != null) {
        sb.append(this.eventdnsLine).append("\n");
      }
      if (this.cachesExtraInfoLine != null) {
        sb.append(this.cachesExtraInfoLine).append("\n");
      }
      if (this.extraInfoDigestLine != null) {
        sb.append(this.extraInfoDigestLine).append("\n");
      }
      if (this.hiddenServiceDirLine != null) {
        sb.append(this.hiddenServiceDirLine).append("\n");
      }
      if (this.protocolsLine != null) {
        sb.append(this.protocolsLine).append("\n");
      }
      if (this.protoLine != null) {
        sb.append(this.protoLine).append("\n");
      }
      if (this.allowSingleHopExitsLine != null) {
        sb.append(this.allowSingleHopExitsLine).append("\n");
      }
      if (this.ipv6PolicyLine != null) {
        sb.append(this.ipv6PolicyLine).append("\n");
      }
      if (this.ntorOnionKeyLine != null) {
        sb.append(this.ntorOnionKeyLine).append("\n");
      }
      if (this.tunnelledDirServerLine != null) {
        sb.append(this.tunnelledDirServerLine).append("\n");
      }
      if (this.unrecognizedLine != null) {
        sb.append(this.unrecognizedLine).append("\n");
      }
      if (this.nonAsciiLineBytes != null) {
        try {
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          baos.write(sb.toString().getBytes());
          baos.write(this.nonAsciiLineBytes);
          baos.write("\n".getBytes());
          if (this.routerSignatureLines != null) {
            baos.write(this.routerSignatureLines.getBytes());
          }
          return baos.toByteArray();
        } catch (IOException e) {
          return null;
        }
      }
      if (this.routerSigEd25519Line != null) {
        sb.append(this.routerSigEd25519Line).append("\n");
      }
      if (this.routerSignatureLines != null) {
        sb.append(this.routerSignatureLines).append("\n");
      }
      return sb.toString().getBytes();
    }

    private ServerDescriptorImpl buildDescriptor(
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      byte[] descriptorBytes = this.buildDescriptorBytes();
      return new RelayServerDescriptorImpl(descriptorBytes,
          new int[] { 0, descriptorBytes.length },
          failUnrecognizedDescriptorLines);
    }
  }

  @Test()
  public void testSampleDescriptor() throws DescriptorParseException {
    DescriptorBuilder db = new DescriptorBuilder();
    ServerDescriptor descriptor = db.buildDescriptor(true);
    assertEquals("saberrider2008", descriptor.getNickname());
    assertEquals("94.134.192.243", descriptor.getAddress());
    assertEquals(9001, (int) descriptor.getOrPort());
    assertEquals(0, (int) descriptor.getSocksPort());
    assertEquals(0, (int) descriptor.getDirPort());
    assertEquals("Tor 0.2.2.35 (git-b04388f9e7546a9f) on Linux i686",
        descriptor.getPlatform());
    assertEquals(new TreeSet<Long>(Arrays.asList(
        new Long[] { 1L, 2L, 3L, 4L })), descriptor.getProtocols().get("Link"));
    assertEquals(new TreeSet<Long>(Arrays.asList(
        new Long[] { 1L })), descriptor.getProtocols().get("LinkAuth"));
    assertEquals(1325390599000L, descriptor.getPublishedMillis());
    assertEquals("D8733048FC8EC9102466AD8F3098622BF1BF71FD",
        descriptor.getFingerprint());
    assertEquals(48, descriptor.getUptime().longValue());
    assertEquals(51200, (int) descriptor.getBandwidthRate());
    assertEquals(51200, (int) descriptor.getBandwidthBurst());
    assertEquals(53470, (int) descriptor.getBandwidthObserved());
    assertEquals("1469D1550738A25B1E7B47CDDBCD7B2899F51B74",
        descriptor.getExtraInfoDigestSha1Hex());
    assertEquals(Arrays.asList(new Integer[] {2}),
        descriptor.getHiddenServiceDirVersions());
    assertEquals("Random Person <nobody AT example dot com>",
        descriptor.getContact());
    assertEquals(Arrays.asList(new String[] {"reject *:*"}),
        descriptor.getExitPolicyLines());
    assertFalse(descriptor.isHibernating());
    assertNull(descriptor.getFamilyEntries());
    assertNull(descriptor.getReadHistory());
    assertNull(descriptor.getWriteHistory());
    assertFalse(descriptor.getUsesEnhancedDnsLogic());
    assertFalse(descriptor.getCachesExtraInfo());
    assertFalse(descriptor.getAllowSingleHopExits());
    assertTrue(descriptor.getUnrecognizedLines().isEmpty());
  }

  @Test(expected = DescriptorParseException.class)
  public void testRouterLineMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine(null);
  }

  @Test()
  public void testRouterOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithRouterLine("opt router saberrider2008 "
        + "94.134.192.243 9001 0 0");
    assertEquals("saberrider2008", descriptor.getNickname());
    assertEquals("94.134.192.243", descriptor.getAddress());
    assertEquals(9001, (int) descriptor.getOrPort());
    assertEquals(0, (int) descriptor.getSocksPort());
    assertEquals(0, (int) descriptor.getDirPort());
  }

  @Test(expected = DescriptorParseException.class)
  public void testRouterLinePrecedingHibernatingLine()
      throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("hibernating 1\nrouter "
        + "saberrider2008 94.134.192.243 9001 0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNicknameMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router  94.134.192.243 9001 "
        + "0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNicknameInvalidChar() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router $aberrider2008 "
        + "94.134.192.243 9001 0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNicknameTooLong() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router "
        + "saberrider2008ReallyLongNickname 94.134.192.243 9001 0 0");
  }

  @Test()
  public void testNicknameTwoSpaces() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithRouterLine("router saberrider2008  "
        + "94.134.192.243 9001 0 0");
    assertEquals("saberrider2008", descriptor.getNickname());
    assertEquals("94.134.192.243", descriptor.getAddress());
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddress24() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008 "
        + "94.134.192/24 9001 0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddress294() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008 "
        + "294.134.192.243 9001 0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddressMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008  9001 "
        + "0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testOrPort99001() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008 "
        + "94.134.192.243 99001 0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testOrPortMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008 "
        + "94.134.192.243  0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testOrPortOne() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008 "
        + "94.134.192.243 one 0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testOrPortNewline() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008 "
        + "94.134.192.243 0\n 0 0");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirPortMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterLine("router saberrider2008 "
        + "94.134.192.243 9001 0 ");
  }

  @Test()
  public void testPlatformMissing() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithPlatformLine(null);
    assertNull(descriptor.getPlatform());
  }

  @Test()
  public void testPlatformOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithPlatformLine("opt platform Tor 0.2.2.35 "
        + "(git-b04388f9e7546a9f) on Linux i686");
    assertEquals("Tor 0.2.2.35 (git-b04388f9e7546a9f) on Linux i686",
        descriptor.getPlatform());
  }

  @Test()
  public void testPlatformNoSpace() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithPlatformLine("platform");
    assertEquals("", descriptor.getPlatform());
  }

  @Test()
  public void testPlatformSpace() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithPlatformLine("platform ");
    assertEquals("", descriptor.getPlatform());
  }

  @Test()
  public void testProtocolsOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithProtocolsLine("opt protocols Link 1 2 Circuit 1");
    assertEquals(Arrays.asList(new Integer[] {1, 2}),
        descriptor.getLinkProtocolVersions());
    assertEquals(Arrays.asList(new Integer[] {1}),
        descriptor.getCircuitProtocolVersions());
  }

  @Test()
  public void testProtocolsNoOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithProtocolsLine("protocols Link 1 2 Circuit 1");
    assertEquals(Arrays.asList(new Integer[] {1, 2}),
        descriptor.getLinkProtocolVersions());
    assertEquals(Arrays.asList(new Integer[] {1}),
        descriptor.getCircuitProtocolVersions());
  }

  @Test(expected = DescriptorParseException.class)
  public void testProtocolsAb() throws DescriptorParseException {
    DescriptorBuilder.createWithProtocolsLine("opt protocols Link A B "
        + "Circuit 1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testProtocolsNoCircuitVersions()
      throws DescriptorParseException {
    DescriptorBuilder.createWithProtocolsLine("opt protocols Link 1 2");
  }

  @Test()
  public void testProtoGreenPurple() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithProtoLine("proto Green=23 Purple=42");
    assertEquals(new TreeSet<Long>(Arrays.asList(new Long[] { 23L })),
        descriptor.getProtocols().get("Green"));
    assertEquals(new TreeSet<Long>(Arrays.asList(new Long[] { 42L })),
        descriptor.getProtocols().get("Purple"));
  }

  @Test(expected = DescriptorParseException.class)
  public void testProtoInvalid() throws DescriptorParseException {
    DescriptorBuilder.createWithProtoLine("proto Invalid=1+2+3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublishedMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithPublishedLine(null);
  }

  @Test()
  public void testPublishedOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithPublishedLine("opt published 2012-01-01 04:03:19");
    assertEquals(1325390599000L, descriptor.getPublishedMillis());
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublished2039() throws DescriptorParseException {
    DescriptorBuilder.createWithPublishedLine("published 2039-01-01 "
        + "04:03:19");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublished1912() throws DescriptorParseException {
    DescriptorBuilder.createWithPublishedLine("published 1912-01-01 "
        + "04:03:19");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublishedFeb31() throws DescriptorParseException {
    DescriptorBuilder.createWithPublishedLine("published 2012-02-31 "
        + "04:03:19");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublishedNoTime() throws DescriptorParseException {
    DescriptorBuilder.createWithPublishedLine("published 2012-01-01");
  }

  @Test()
  public void testPublishedMillis() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithPublishedLine("opt published 2012-01-01 04:03:19.123");
    assertEquals(1325390599000L, descriptor.getPublishedMillis());
  }

  @Test()
  public void testFingerprintNoOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithFingerprintLine("fingerprint D873 3048 FC8E C910 2466 "
            + "AD8F 3098 622B F1BF 71FD");
    assertEquals("D8733048FC8EC9102466AD8F3098622BF1BF71FD",
        descriptor.getFingerprint());
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintG() throws DescriptorParseException {
    DescriptorBuilder.createWithFingerprintLine("opt fingerprint G873 "
        + "3048 FC8E C910 2466 AD8F 3098 622B F1BF 71FD");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintTooShort() throws DescriptorParseException {
    DescriptorBuilder.createWithFingerprintLine("opt fingerprint D873 "
        + "3048 FC8E C910 2466 AD8F 3098 622B F1BF");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintTooLong() throws DescriptorParseException {
    DescriptorBuilder.createWithFingerprintLine("opt fingerprint D873 "
        + "3048 FC8E C910 2466 AD8F 3098 622B F1BF 71FD D873");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintNoSpaces() throws DescriptorParseException {
    DescriptorBuilder.createWithFingerprintLine("opt fingerprint "
        + "D8733048FC8EC9102466AD8F3098622BF1BF71FD");
  }

  @Test()
  public void testUptimeMissing() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithUptimeLine(null);
    assertNull(descriptor.getUptime());
  }

  @Test()
  public void testUptimeOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithUptimeLine("opt uptime 48");
    assertEquals(48, descriptor.getUptime().longValue());
  }

  @Test(expected = DescriptorParseException.class)
  public void testUptimeFourtyEight() throws DescriptorParseException {
    DescriptorBuilder.createWithUptimeLine("uptime fourty-eight");
  }

  @Test()
  public void testUptimeMinusOne() throws DescriptorParseException {
    DescriptorBuilder.createWithUptimeLine("uptime -1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testUptimeSpace() throws DescriptorParseException {
    DescriptorBuilder.createWithUptimeLine("uptime ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testUptimeNoSpace() throws DescriptorParseException {
    DescriptorBuilder.createWithUptimeLine("uptime");
  }

  @Test(expected = DescriptorParseException.class)
  public void testUptimeFourEight() throws DescriptorParseException {
    DescriptorBuilder.createWithUptimeLine("uptime 4 8");
  }

  @Test()
  public void testBandwidthOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithBandwidthLine("opt bandwidth 51200 51200 53470");
    assertEquals(51200, (int) descriptor.getBandwidthRate());
    assertEquals(51200, (int) descriptor.getBandwidthBurst());
    assertEquals(53470, (int) descriptor.getBandwidthObserved());
  }

  @Test(expected = DescriptorParseException.class)
  public void testBandwidthMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithBandwidthLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testBandwidthOneValue() throws DescriptorParseException {
    DescriptorBuilder.createWithBandwidthLine("bandwidth 51200");
  }

  @Test()
  public void testBandwidthTwoValues() throws DescriptorParseException {
    /* This is allowed, because Tor versions 0.0.8 and older only wrote
     * bandwidth lines with rate and burst values, but no observed
     * value. */
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithBandwidthLine("bandwidth 51200 51200");
    assertEquals(51200, (int) descriptor.getBandwidthRate());
    assertEquals(51200, (int) descriptor.getBandwidthBurst());
    assertEquals(-1, (int) descriptor.getBandwidthObserved());
  }

  @Test(expected = DescriptorParseException.class)
  public void testBandwidthFourValues() throws DescriptorParseException {
    DescriptorBuilder.createWithBandwidthLine("bandwidth 51200 51200 "
        + "53470 53470");
  }

  @Test(expected = DescriptorParseException.class)
  public void testBandwidthMinusOneTwoThree()
      throws DescriptorParseException {
    DescriptorBuilder.createWithBandwidthLine("bandwidth -1 -2 -3");
  }

  @Test()
  public void testExtraInfoDigestNoOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithExtraInfoDigestLine("extra-info-digest "
        + "1469D1550738A25B1E7B47CDDBCD7B2899F51B74");
    assertEquals("1469D1550738A25B1E7B47CDDBCD7B2899F51B74",
        descriptor.getExtraInfoDigestSha1Hex());
  }

  @Test(expected = DescriptorParseException.class)
  public void testExtraInfoDigestNoSpace()
      throws DescriptorParseException {
    DescriptorBuilder.createWithExtraInfoDigestLine("opt "
        + "extra-info-digest");
  }

  @Test(expected = DescriptorParseException.class)
  public void testExtraInfoDigestTooShort()
      throws DescriptorParseException {
    DescriptorBuilder.createWithExtraInfoDigestLine("opt "
        + "extra-info-digest 1469D1550738A25B1E7B47CDDBCD7B2899F5");
  }

  @Test(expected = DescriptorParseException.class)
  public void testExtraInfoDigestTooLong()
      throws DescriptorParseException {
    DescriptorBuilder.createWithExtraInfoDigestLine("opt "
        + "extra-info-digest "
        + "1469D1550738A25B1E7B47CDDBCD7B2899F51B741469");
  }

  @Test()
  public void testExtraInfoDigestMissing()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithExtraInfoDigestLine(null);
    assertNull(descriptor.getExtraInfoDigestSha1Hex());
  }

  @Test()
  public void testExtraInfoDigestAdditionalDigest()
      throws DescriptorParseException {
    String extraInfoDigest = "0879DB7B765218D7B3AE7557669D20307BB21CAA";
    String additionalExtraInfoDigest =
        "V609l+N6ActBveebfNbH5lQ6wHDNstDkFgyqEhBHwtA";
    String extraInfoDigestLine = String.format("extra-info-digest %s %s",
        extraInfoDigest, additionalExtraInfoDigest);
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithExtraInfoDigestLine(extraInfoDigestLine);
    assertEquals(extraInfoDigest, descriptor.getExtraInfoDigestSha1Hex());
  }

  @Test()
  public void testOnionKeyOpt() throws DescriptorParseException {
    DescriptorBuilder.createWithOnionKeyLines("opt onion-key\n"
        + "-----BEGIN RSA PUBLIC KEY-----\n"
        + "MIGJAoGBAKM+iiHhO6eHsvd6Xjws9z9EQB1V/Bpuy5ciGJ1U4V9SeiKooSo5Bp"
        + "PL\no3XT+6PIgzl3R6uycjS3Ejk47vLEJdcVTm/VG6E0ppu3olIynCI4QryfCE"
        + "uC3cTF\n9wE4WXY4nX7w0RTN18UVLxrt1A9PP0cobFNiPs9rzJCbKFfacOkpAg"
        + "MBAAE=\n"
        + "-----END RSA PUBLIC KEY-----");
  }

  @Test()
  public void testSigningKeyOpt() throws DescriptorParseException {
    DescriptorBuilder.createWithSigningKeyLines("opt signing-key\n"
        + "-----BEGIN RSA PUBLIC KEY-----\n"
        + "MIGJAoGBALMm3r3QDh482Ewe6Ub9wvRIfmEkoNX6q5cEAtQRNHSDcNx41gjELb"
        + "cl\nEniVMParBYACKfOxkS+mTTnIRDKVNEJTsDOwryNrc4X9JnPc/nn6ymYPiN"
        + "DhUROG\n8URDIhQoixcUeyyrVB8sxliSstKimulGnB7xpjYOlO8JKaHLNL4TAg"
        + "MBAAE=\n"
        + "-----END RSA PUBLIC KEY-----");
  }

  @Test()
  public void testHiddenServiceDirMissing()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithHiddenServiceDirLine(null);
    assertNull(descriptor.getHiddenServiceDirVersions());
  }

  @Test()
  public void testHiddenServiceDirNoOpt()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithHiddenServiceDirLine("hidden-service-dir");
    assertEquals(Arrays.asList(new Integer[] {2}),
        descriptor.getHiddenServiceDirVersions());
  }

  @Test()
  public void testHiddenServiceDirVersions2And3()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithHiddenServiceDirLine("hidden-service-dir 2 3");
    assertEquals(Arrays.asList(new Integer[] {2, 3}),
        descriptor.getHiddenServiceDirVersions());
  }

  @Test()
  public void testContactMissing() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithContactLine(null);
    assertNull(descriptor.getContact());
  }

  @Test()
  public void testContactOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithContactLine("opt contact Random Person");
    assertEquals("Random Person", descriptor.getContact());
  }

  @Test(expected = DescriptorParseException.class)
  public void testContactDuplicate() throws DescriptorParseException {
    DescriptorBuilder.createWithContactLine("contact Random "
        + "Person\ncontact Random Person");
  }

  @Test()
  public void testContactNoSpace() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithContactLine("contact");
    assertEquals("", descriptor.getContact());
  }

  @Test()
  public void testContactCarriageReturn()
      throws DescriptorParseException {
    String contactString = "Random "
        + "Person -----BEGIN PGP PUBLIC KEY BLOCK-----\r"
        + "Version: GnuPG v1 dot 4 dot 7 (Darwin)\r\r"
        + "mQGiBEbb0rcRBADqBiUXsmtpJifh74irNnkHbhKMj8O4TqenaZYhdjLWouZsZd"
        + "07\rmTQoP40G4zqOrVEOOcXpdSiRnHWJYfgTnkibNZrOZEZLn3H1ywpovEgESm"
        + "oGEdAX\roid3XuIYRpRnqoafbFg9sg+OofX/mGrO+5ACfagQ9rlfx2oxCWijYw"
        + "pYFRk3NhCY=\r=Xaw3\r-----END PGP PUBLIC KEY BLOCK-----";
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithContactLine("contact " + contactString);
    assertEquals(contactString, descriptor.getContact());
  }

  @Test()
  public void testExitPolicyRejectAllAcceptAll()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithExitPolicyLines("reject *:*\naccept *:*");
    assertEquals(Arrays.asList(new String[] {"reject *:*", "accept *:*"}),
        descriptor.getExitPolicyLines());
  }

  @Test()
  public void testExitPolicyOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithExitPolicyLines("opt reject *:*");
    assertEquals(Arrays.asList(new String[] {"reject *:*"}),
        descriptor.getExitPolicyLines());
  }

  @Test(expected = DescriptorParseException.class)
  public void testExitPolicyNoPort() throws DescriptorParseException {
    DescriptorBuilder.createWithExitPolicyLines("reject *");
  }

  @Test()
  public void testExitPolicyAccept80RejectAll()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithExitPolicyLines("accept *:80\nreject *:*");
    assertEquals(Arrays.asList(new String[] {"accept *:80",
        "reject *:*"}), descriptor.getExitPolicyLines());
  }

  @Test(expected = DescriptorParseException.class)
  public void testExitPolicyReject321() throws DescriptorParseException {
    DescriptorBuilder.createWithExitPolicyLines("reject "
        + "123.123.123.321:80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testExitPolicyRejectPort66666()
      throws DescriptorParseException {
    DescriptorBuilder.createWithExitPolicyLines("reject *:66666");
  }

  @Test(expected = DescriptorParseException.class)
  public void testExitPolicyProjectAll() throws DescriptorParseException {
    DescriptorBuilder.createWithExitPolicyLines("project *:*");
  }

  @Test(expected = DescriptorParseException.class)
  public void testExitPolicyMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithExitPolicyLines(null);
  }

  @Test()
  public void testExitPolicyMaskTypes() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithExitPolicyLines("reject 192.168.0.0/16:*\n"
        + "reject 94.134.192.243/255.255.255.0:*");
    assertEquals(Arrays.asList(new String[] { "reject 192.168.0.0/16:*",
        "reject 94.134.192.243/255.255.255.0:*"}),
        descriptor.getExitPolicyLines());
  }

  @Test(expected = DescriptorParseException.class)
  public void testEndSignatureFourDashes() throws DescriptorParseException {
    DescriptorBuilder.createWithRouterSignatureLines("router-signature\n"
        + "-----BEGIN SIGNATURE-----\n"
        + "o4j+kH8UQfjBwepUnr99v0ebN8RpzHJ/lqYsTojXHy9kMr1RNI9IDeSzA7PSqT"
        + "uV\n4PL8QsGtlfwthtIoZpB2srZeyN/mcpA9fa1JXUrt/UN9K/+32Cyaad7h0n"
        + "HE6Xfb\njqpXDpnBpvk4zjmzjjKYnIsUWTnADmu0fo3xTRqXi7g=\n"
        + "-----END SIGNATURE----");
  }

  @Test(expected = DescriptorParseException.class)
  public void testRouterSignatureNotLastLine()
      throws DescriptorParseException {
    DescriptorBuilder.createWithRouterSignatureLines("router-signature\n"
        + "-----BEGIN SIGNATURE-----\n"
        + "o4j+kH8UQfjBwepUnr99v0ebN8RpzHJ/lqYsTojXHy9kMr1RNI9IDeSzA7PSqT"
        + "uV\n4PL8QsGtlfwthtIoZpB2srZeyN/mcpA9fa1JXUrt/UN9K/+32Cyaad7h0n"
        + "HE6Xfb\njqpXDpnBpvk4zjmzjjKYnIsUWTnADmu0fo3xTRqXi7g=\n"
        + "-----END SIGNATURE-----\ncontact me");
  }

  @Test()
  public void testHibernatingOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithHibernatingLine("opt hibernating 1");
    assertTrue(descriptor.isHibernating());
  }

  @Test()
  public void testHibernatingFalse() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithHibernatingLine("hibernating 0");
    assertFalse(descriptor.isHibernating());
  }

  @Test()
  public void testHibernatingTrue() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithHibernatingLine("hibernating 1");
    assertTrue(descriptor.isHibernating());
  }

  @Test(expected = DescriptorParseException.class)
  public void testHibernatingYep() throws DescriptorParseException {
    DescriptorBuilder.createWithHibernatingLine("hibernating yep");
  }

  @Test(expected = DescriptorParseException.class)
  public void testHibernatingNoSpace() throws DescriptorParseException {
    DescriptorBuilder.createWithHibernatingLine("hibernating");
  }

  @Test()
  public void testFamilyOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithFamilyLine("opt family saberrider2008");
    assertEquals(Arrays.asList(new String[] {"saberrider2008"}),
        descriptor.getFamilyEntries());
  }

  @Test()
  public void testFamilyFingerprint() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithFamilyLine("family "
        + "$D8733048FC8EC9102466AD8F3098622BF1BF71FD");
    assertEquals(Arrays.asList(new String[] {
        "$D8733048FC8EC9102466AD8F3098622BF1BF71FD"}),
        descriptor.getFamilyEntries());
  }

  @Test()
  public void testFamilyNickname() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithFamilyLine("family saberrider2008");
    assertEquals(Arrays.asList(new String[] {"saberrider2008"}),
        descriptor.getFamilyEntries());
  }

  @Test(expected = DescriptorParseException.class)
  public void testFamilyDuplicate() throws DescriptorParseException {
    DescriptorBuilder.createWithFamilyLine("family "
        + "saberrider2008\nfamily saberrider2008");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFamilyNicknamePrefix() throws DescriptorParseException {
    DescriptorBuilder.createWithFamilyLine("family $saberrider2008");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFamilyFingerprintNoPrefix()
      throws DescriptorParseException {
    DescriptorBuilder.createWithFamilyLine("family "
        + "D8733048FC8EC9102466AD8F3098622BF1BF71FD");
  }

  @Test()
  public void testFamilyFingerprintNicknameNamed()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithFamilyLine("family "
        + "$D8733048FC8EC9102466AD8F3098622BF1BF71FD=saberrider2008");
    assertEquals(Arrays.asList(new String[]
        { "$D8733048FC8EC9102466AD8F3098622BF1BF71FD=saberrider2008" }),
        descriptor.getFamilyEntries());
  }

  @Test()
  public void testFamilyFingerprintNicknameUnnamed()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithFamilyLine("family "
        + "$D8733048FC8EC9102466AD8F3098622BF1BF71FD~saberrider2008");
    assertEquals(Arrays.asList(new String[]
        { "$D8733048FC8EC9102466AD8F3098622BF1BF71FD~saberrider2008" }),
        descriptor.getFamilyEntries());
  }

  @Test()
  public void testWriteHistory() throws DescriptorParseException {
    String writeHistoryLine = "write-history 2012-01-01 03:51:44 (900 s) "
        + "4345856,261120,7591936,1748992";
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithWriteHistoryLine(writeHistoryLine);
    assertNotNull(descriptor.getWriteHistory());
    BandwidthHistory parsedWriteHistory = descriptor.getWriteHistory();
    assertEquals(writeHistoryLine, parsedWriteHistory.getLine());
    assertEquals(1325389904000L, (long) parsedWriteHistory
        .getHistoryEndMillis());
    assertEquals(900L, (long) parsedWriteHistory.getIntervalLength());
    SortedMap<Long, Long> bandwidthValues = parsedWriteHistory
        .getBandwidthValues();
    assertEquals(4345856L, (long) bandwidthValues.remove(1325387204000L));
    assertEquals(261120L, (long) bandwidthValues.remove(1325388104000L));
    assertEquals(7591936L, (long) bandwidthValues.remove(1325389004000L));
    assertEquals(1748992L, (long) bandwidthValues.remove(1325389904000L));
    assertTrue(bandwidthValues.isEmpty());
  }

  @Test()
  public void testWriteHistoryOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithWriteHistoryLine("opt write-history 2012-01-01 "
        + "03:51:44 (900 s) 4345856,261120,7591936,1748992");
    assertNotNull(descriptor.getWriteHistory());
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistory3012() throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "3012-01-01 03:51:44 (900 s) 4345856,261120,7591936,1748992");
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryNoSeconds()
      throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "2012-01-01 03:51 (900 s) 4345856,261120,7591936,1748992");
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryNoParathenses()
      throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "2012-01-01 03:51:44 900 s 4345856,261120,7591936,1748992");
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryNoSpaceSeconds()
      throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "2012-01-01 03:51:44 (900s) 4345856,261120,7591936,1748992");
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryTrailingComma()
      throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "2012-01-01 03:51:44 (900 s) 4345856,261120,7591936,");
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryOneTwoThree()
      throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "2012-01-01 03:51:44 (900 s) one,two,three");
  }

  @Test()
  public void testWriteHistoryNoValuesSpace()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithWriteHistoryLine("write-history 2012-01-01 03:51:44 "
        + "(900 s) ");
    assertEquals(900, (long) descriptor.getWriteHistory()
        .getIntervalLength());
    assertTrue(descriptor.getWriteHistory().getBandwidthValues()
        .isEmpty());
  }

  @Test()
  public void testWriteHistoryNoValuesNoSpace()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithWriteHistoryLine("write-history 2012-01-01 03:51:44 "
        + "(900 s)");
    assertEquals(900, (long) descriptor.getWriteHistory()
        .getIntervalLength());
    assertTrue(descriptor.getWriteHistory().getBandwidthValues()
        .isEmpty());
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryNoS() throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine(
        "write-history 2012-01-01 03:51:44 (900 ");
  }

  @Test()
  public void testWriteHistoryExtraArg()
      throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "2012-01-01 03:51:44 (900 s) 4345856 bin_size=1024");
  }

  @Test()
  public void testWriteHistory1800Seconds()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithWriteHistoryLine("write-history 2012-01-01 03:51:44 "
        + "(1800 s) 4345856");
    assertEquals(1800L, (long) descriptor.getWriteHistory()
        .getIntervalLength());
  }

  @Test()
  public void testReadHistory() throws DescriptorParseException {
    String readHistoryLine = "read-history 2012-01-01 03:51:44 (900 s) "
        + "4268032,139264,7797760,1415168";
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithReadHistoryLine(readHistoryLine);
    assertNotNull(descriptor.getReadHistory());
    BandwidthHistory parsedReadHistory = descriptor.getReadHistory();
    assertEquals(readHistoryLine, parsedReadHistory.getLine());
    assertEquals(1325389904000L, (long) parsedReadHistory
        .getHistoryEndMillis());
    assertEquals(900L, (long) parsedReadHistory.getIntervalLength());
    SortedMap<Long, Long> bandwidthValues = parsedReadHistory
        .getBandwidthValues();
    assertEquals(4268032L, (long) bandwidthValues.remove(1325387204000L));
    assertEquals(139264L, (long) bandwidthValues.remove(1325388104000L));
    assertEquals(7797760L, (long) bandwidthValues.remove(1325389004000L));
    assertEquals(1415168L, (long) bandwidthValues.remove(1325389904000L));
    assertTrue(bandwidthValues.isEmpty());
  }

  @Test()
  public void testReadHistoryTwoSpaces() throws DescriptorParseException {
    /* There are some server descriptors from older Tor versions that
     * contain "opt read-history  " lines. */
    String readHistoryLine = "opt read-history  2012-01-01 03:51:44 "
        + "(900 s) 4268032,139264,7797760,1415168";
    DescriptorBuilder.createWithReadHistoryLine(readHistoryLine);
  }

  @Test()
  public void testEventdnsOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithEventdnsLine("opt eventdns 1");
    assertTrue(descriptor.getUsesEnhancedDnsLogic());
  }

  @Test()
  public void testEventdns1() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithEventdnsLine("eventdns 1");
    assertTrue(descriptor.getUsesEnhancedDnsLogic());
  }

  @Test()
  public void testEventdns0() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithEventdnsLine("eventdns 0");
    assertFalse(descriptor.getUsesEnhancedDnsLogic());
  }

  @Test(expected = DescriptorParseException.class)
  public void testEventdnsTrue() throws DescriptorParseException {
    DescriptorBuilder.createWithEventdnsLine("eventdns true");
  }

  @Test(expected = DescriptorParseException.class)
  public void testEventdnsNo() throws DescriptorParseException {
    DescriptorBuilder.createWithEventdnsLine("eventdns no");
  }

  @Test()
  public void testCachesExtraInfoOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithCachesExtraInfoLine("opt caches-extra-info");
    assertTrue(descriptor.getCachesExtraInfo());
  }

  @Test()
  public void testCachesExtraInfoNoSpace()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithCachesExtraInfoLine("caches-extra-info");
    assertTrue(descriptor.getCachesExtraInfo());
  }

  @Test(expected = DescriptorParseException.class)
  public void testCachesExtraInfoTrue() throws DescriptorParseException {
    DescriptorBuilder.createWithCachesExtraInfoLine("caches-extra-info "
        + "true");
  }

  @Test()
  public void testAllowSingleHopExitsOpt()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithAllowSingleHopExitsLine("opt allow-single-hop-exits");
    assertTrue(descriptor.getAllowSingleHopExits());
  }

  @Test()
  public void testAllowSingleHopExitsNoSpace()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithAllowSingleHopExitsLine("allow-single-hop-exits");
    assertTrue(descriptor.getAllowSingleHopExits());
  }

  @Test(expected = DescriptorParseException.class)
  public void testAllowSingleHopExitsTrue()
      throws DescriptorParseException {
    DescriptorBuilder.createWithAllowSingleHopExitsLine(
        "allow-single-hop-exits true");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAllowSingleHopExitsNonAsciiKeyword()
      throws DescriptorParseException {
    DescriptorBuilder.createWithNonAsciiLineBytes(new byte[] {
        0x14, (byte) 0xfe, 0x18,                  // non-ascii chars
        0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x2d,       // "allow-"
        0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x2d, // "single-"
        0x68, 0x6f, 0x70, 0x2d,                   // "hop-"
        0x65, 0x78, 0x69, 0x74, 0x73 },           // "exits" (no newline)
        false);
  }

  @Test()
  public void testIpv6PolicyLine() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithIpv6PolicyLine("ipv6-policy accept 80,1194,1220,1293");
    assertEquals("accept", descriptor.getIpv6DefaultPolicy());
    assertEquals("80,1194,1220,1293", descriptor.getIpv6PortList());
  }

  @Test(expected = DescriptorParseException.class)
  public void testIpv6PolicyLineNoPolicy()
      throws DescriptorParseException {
    DescriptorBuilder.createWithIpv6PolicyLine("ipv6-policy 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testIpv6PolicyLineNoPorts()
      throws DescriptorParseException {
    DescriptorBuilder.createWithIpv6PolicyLine("ipv6-policy accept");
  }

  @Test(expected = DescriptorParseException.class)
  public void testIpv6PolicyLineNoPolicyNoPorts()
      throws DescriptorParseException {
    DescriptorBuilder.createWithIpv6PolicyLine("ipv6-policy ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testIpv6PolicyLineProject()
      throws DescriptorParseException {
    DescriptorBuilder.createWithIpv6PolicyLine("ipv6-policy project 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testTwoIpv6PolicyLines() throws DescriptorParseException {
    DescriptorBuilder.createWithIpv6PolicyLine(
        "ipv6-policy accept 80,1194,1220,1293\n"
        + "ipv6-policy accept 80,1194,1220,1293");
  }

  @Test()
  public void testNtorOnionKeyLine() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithNtorOnionKeyLine("ntor-onion-key "
        + "Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY=");
    assertEquals("Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY",
        descriptor.getNtorOnionKey());
  }

  @Test()
  public void testNtorOnionKeyLineNoPadding()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithNtorOnionKeyLine("ntor-onion-key "
        + "Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY");
    assertEquals("Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY",
        descriptor.getNtorOnionKey());
  }

  @Test(expected = DescriptorParseException.class)
  public void testNtorOnionKeyLineNoKey()
      throws DescriptorParseException {
    DescriptorBuilder.createWithNtorOnionKeyLine("ntor-onion-key ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNtorOnionKeyLineTwoKeys()
      throws DescriptorParseException {
    DescriptorBuilder.createWithNtorOnionKeyLine("ntor-onion-key "
        + "Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY "
        + "Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY");
  }

  @Test(expected = DescriptorParseException.class)
  public void testTwoNtorOnionKeyLines() throws DescriptorParseException {
    DescriptorBuilder.createWithNtorOnionKeyLine("ntor-onion-key "
        + "Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY\nntor-onion-key "
        + "Y/XgaHcPIJVa4D55kir9QLH8rEYAaLXuv3c3sm8jYhY\n");
  }

  @Test()
  public void testTunnelledDirServerTrue()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithTunnelledDirServerLine("tunnelled-dir-server");
    assertTrue(descriptor.getTunnelledDirServer());
  }

  @Test()
  public void testTunnelledDirServerFalse()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithTunnelledDirServerLine(null);
    assertFalse(descriptor.getTunnelledDirServer());
  }

  @Test(expected = DescriptorParseException.class)
  public void testTunnelledDirServerTypo()
      throws DescriptorParseException {
    DescriptorBuilder.createWithTunnelledDirServerLine(
        "tunneled-dir-server");
  }

  @Test(expected = DescriptorParseException.class)
  public void testTunnelledDirServerTwice()
      throws DescriptorParseException {
    DescriptorBuilder.createWithTunnelledDirServerLine(
        "tunnelled-dir-server\ntunnelled-dir-server");
  }

  @Test(expected = DescriptorParseException.class)
  public void testTunnelledDirServerArgs()
      throws DescriptorParseException {
    DescriptorBuilder.createWithTunnelledDirServerLine(
        "tunnelled-dir-server 1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testUnrecognizedLineFail()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    DescriptorBuilder.createWithUnrecognizedLine(unrecognizedLine, true);
  }

  @Test()
  public void testUnrecognizedLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithUnrecognizedLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, descriptor.getUnrecognizedLines());
  }

  @Test()
  public void testSomeOtherKey() throws DescriptorParseException {
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add("some-other-key");
    unrecognizedLines.add("-----BEGIN RSA PUBLIC KEY-----");
    unrecognizedLines.add("MIGJAoGBAKM+iiHhO6eHsvd6Xjws9z9EQB1V/Bpuy5ciGJ"
        + "1U4V9SeiKooSo5BpPL");
    unrecognizedLines.add("o3XT+6PIgzl3R6uycjS3Ejk47vLEJdcVTm/VG6E0ppu3ol"
        + "IynCI4QryfCEuC3cTF");
    unrecognizedLines.add("9wE4WXY4nX7w0RTN18UVLxrt1A9PP0cobFNiPs9rzJCbKF"
        + "facOkpAgMBAAE=");
    unrecognizedLines.add("-----END RSA PUBLIC KEY-----");
    StringBuilder sb = new StringBuilder();
    for (String line : unrecognizedLines) {
      sb.append("\n").append(line);
    }
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithUnrecognizedLine(sb.toString().substring(1), false);
    assertEquals(unrecognizedLines, descriptor.getUnrecognizedLines());
  }

  @Test()
  public void testUnrecognizedCryptoBlockNoKeyword()
      throws DescriptorParseException {
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add("-----BEGIN RSA PUBLIC KEY-----");
    unrecognizedLines.add("MIGJAoGBAKM+iiHhO6eHsvd6Xjws9z9EQB1V/Bpuy5ciGJ"
        + "1U4V9SeiKooSo5BpPL");
    unrecognizedLines.add("o3XT+6PIgzl3R6uycjS3Ejk47vLEJdcVTm/VG6E0ppu3ol"
        + "IynCI4QryfCEuC3cTF");
    unrecognizedLines.add("9wE4WXY4nX7w0RTN18UVLxrt1A9PP0cobFNiPs9rzJCbKF"
        + "facOkpAgMBAAE=");
    unrecognizedLines.add("-----END RSA PUBLIC KEY-----");
    StringBuilder sb = new StringBuilder();
    for (String line : unrecognizedLines) {
      sb.append("\n").append(line);
    }
    ServerDescriptor descriptor = DescriptorBuilder
        .createWithUnrecognizedLine(sb.toString().substring(1), false);
    assertEquals(unrecognizedLines, descriptor.getUnrecognizedLines());
  }

  private static final String IDENTITY_ED25519_LINES =
      "identity-ed25519\n"
      + "-----BEGIN ED25519 CERT-----\n"
      + "AQQABiX1AVGv5BuzJroQXbOh6vv1nbwc5rh2S13PyRFuLhTiifK4AQAgBACBCMwr"
      + "\n4qgIlFDIzoC9ieJOtSkwrK+yXJPKlP8ojvgkx8cGKvhokOwA1eYDombzfwHcJ1"
      + "EV\nbhEn/6g8i7wzO3LoqefIUrSAeEExOAOmm5mNmUIzL8EtnT6JHCr/sqUTUgA="
      + "\n"
      + "-----END ED25519 CERT-----";

  private static final String MASTER_KEY_ED25519_LINE =
      "master-key-ed25519 gQjMK+KoCJRQyM6AvYniTrUpMKyvslyTypT/KI74JMc";

  private static final String ROUTER_SIG_ED25519_LINE =
      "router-sig-ed25519 y7WF9T2GFwkSDPZEhB55HgquIFOl5uXUFMYJPq3CXXUTKeJ"
      + "kSrtaZUB5s34fWdHQNtl84mH4dVaFMunHnwgYAw";

  @Test()
  public void testEd25519() throws DescriptorParseException {
    ServerDescriptor descriptor =
        DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES,
        MASTER_KEY_ED25519_LINE, ROUTER_SIG_ED25519_LINE);
    assertEquals(IDENTITY_ED25519_LINES.substring(
        IDENTITY_ED25519_LINES.indexOf("\n") + 1),
        descriptor.getIdentityEd25519());
    assertEquals(MASTER_KEY_ED25519_LINE.substring(
        MASTER_KEY_ED25519_LINE.indexOf(" ") + 1),
        descriptor.getMasterKeyEd25519());
    assertEquals(ROUTER_SIG_ED25519_LINE.substring(
        ROUTER_SIG_ED25519_LINE.indexOf(" ") + 1),
        descriptor.getRouterSignatureEd25519());
  }

  @Test(expected = DescriptorParseException.class)
  public void testEd25519IdentityMasterKeyMismatch()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES,
        "master-key-ed25519 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ROUTER_SIG_ED25519_LINE);
  }

  @Test()
  public void testEd25519IdentityMissing()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines(null,
        MASTER_KEY_ED25519_LINE, ROUTER_SIG_ED25519_LINE);
  }

  @Test(expected = DescriptorParseException.class)
  public void testEd25519IdentityDuplicate()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES + "\n"
        + IDENTITY_ED25519_LINES, MASTER_KEY_ED25519_LINE,
        ROUTER_SIG_ED25519_LINE);
  }

  @Test(expected = DescriptorParseException.class)
  public void testEd25519IdentityEmptyCrypto()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines("identity-ed25519\n"
        + "-----BEGIN ED25519 CERT-----\n-----END ED25519 CERT-----",
        MASTER_KEY_ED25519_LINE, ROUTER_SIG_ED25519_LINE);
  }

  @Test()
  public void testEd25519MasterKeyMissing()
      throws DescriptorParseException {
    ServerDescriptor descriptor =
        DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES,
        null, ROUTER_SIG_ED25519_LINE);
    assertEquals(MASTER_KEY_ED25519_LINE.substring(
        MASTER_KEY_ED25519_LINE.indexOf(" ") + 1),
        descriptor.getMasterKeyEd25519());
  }

  @Test(expected = DescriptorParseException.class)
  public void testEd25519MasterKeyDuplicate()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES,
        MASTER_KEY_ED25519_LINE + "\n" + MASTER_KEY_ED25519_LINE,
        ROUTER_SIG_ED25519_LINE);
  }

  @Test()
  public void testEd25519RouterSigMissing()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES,
        MASTER_KEY_ED25519_LINE, null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testEd25519RouterSigDuplicate()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES,
        MASTER_KEY_ED25519_LINE, ROUTER_SIG_ED25519_LINE + "\n"
        + ROUTER_SIG_ED25519_LINE);
  }

  @Test(expected = DescriptorParseException.class)
  public void testEd25519FollowedbyUnrecognizedLine()
      throws DescriptorParseException {
    DescriptorBuilder.createWithEd25519Lines(IDENTITY_ED25519_LINES,
        MASTER_KEY_ED25519_LINE, ROUTER_SIG_ED25519_LINE
        + "\nunrecognized-line 1");
  }

  private static final String ONION_KEY_CROSSCERT_LINES =
      "onion-key-crosscert\n"
      + "-----BEGIN CROSSCERT-----\n"
      + "gVWpiNgG2FekW1uonr4KKoqykjr4bqUBKGZfu6s9rvsV1TThnquZNP6ZhX2IPdQA"
      + "\nlfKtzFggGu/4BiJ5oTSDj2sK2DMjY3rjrMQZ3I/wJ25yhc9gxjqYqUYO9MmJwA"
      + "Lp\nfYkqp/t4WchJpyva/4hK8vITsI6eT2BfY/DWMy/suIE=\n"
      + "-----END CROSSCERT-----";

  private static final String NTOR_ONION_KEY_CROSSCERT_LINES =
      "ntor-onion-key-crosscert 1\n"
      + "-----BEGIN ED25519 CERT-----\n"
      + "AQoABiUeAdauu1MxYGMmGLTCPaoes0RvW7udeLc1t8LZ4P3CDo5bAN4nrRfbCfOt"
      + "\nz2Nwqn8tER1a+Ry6Vs+ilMZA55Rag4+f6Zdb1fmHWknCxbQlLHpqHACMtemPda"
      + "Ka\nErPtMuiEqAc=\n"
      + "-----END ED25519 CERT-----";

  @Test()
  public void testOnionKeyCrosscert() throws DescriptorParseException {
    ServerDescriptor descriptor =
        DescriptorBuilder.createWithOnionKeyCrosscertLines(
        ONION_KEY_CROSSCERT_LINES);
    assertEquals(ONION_KEY_CROSSCERT_LINES.substring(
        ONION_KEY_CROSSCERT_LINES.indexOf("\n") + 1),
        descriptor.getOnionKeyCrosscert());
  }

  @Test(expected = DescriptorParseException.class)
  public void testOnionKeyCrosscertDuplicate()
      throws DescriptorParseException {
    DescriptorBuilder.createWithOnionKeyCrosscertLines(
        ONION_KEY_CROSSCERT_LINES + "\n" + ONION_KEY_CROSSCERT_LINES);
  }

  @Test()
  public void testNtorOnionKeyCrosscert()
      throws DescriptorParseException {
    ServerDescriptor descriptor =
        DescriptorBuilder.createWithNtorOnionKeyCrosscertLines(
        NTOR_ONION_KEY_CROSSCERT_LINES);
    assertEquals(NTOR_ONION_KEY_CROSSCERT_LINES.substring(
        NTOR_ONION_KEY_CROSSCERT_LINES.indexOf("\n") + 1),
        descriptor.getNtorOnionKeyCrosscert());
    assertEquals(1, descriptor.getNtorOnionKeyCrosscertSign());
  }

  @Test(expected = DescriptorParseException.class)
  public void testNtorOnionKeyCrosscertDuplicate()
      throws DescriptorParseException {
    DescriptorBuilder.createWithOnionKeyCrosscertLines(
        NTOR_ONION_KEY_CROSSCERT_LINES + "\n"
        + NTOR_ONION_KEY_CROSSCERT_LINES);
  }
}

