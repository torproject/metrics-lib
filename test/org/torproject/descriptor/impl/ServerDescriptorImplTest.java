/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;

import org.junit.Test;
import org.torproject.descriptor.BandwidthHistory;
import org.torproject.descriptor.ServerDescriptor;

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
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String bandwidthLine = "bandwidth 51200 51200 53470";
    private static ServerDescriptor createWithBandwidthLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.bandwidthLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String platformLine = "platform Tor 0.2.2.35 "
        + "(git-b04388f9e7546a9f) on Linux i686";
    private static ServerDescriptor createWithPlatformLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.platformLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String publishedLine = "published 2012-01-01 04:03:19";
    private static ServerDescriptor createWithPublishedLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.publishedLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String fingerprintLine = "opt fingerprint D873 3048 FC8E "
        + "C910 2466 AD8F 3098 622B F1BF 71FD";
    private static ServerDescriptor createWithFingerprintLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.fingerprintLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String hibernatingLine = null;
    private static ServerDescriptor createWithHibernatingLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.hibernatingLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String uptimeLine = "uptime 48";
    private static ServerDescriptor createWithUptimeLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.uptimeLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
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
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
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
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String exitPolicyLines = "reject *:*";
    private static ServerDescriptor createWithExitPolicyLines(
        String lines) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.exitPolicyLines = lines;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String contactLine = "contact Random Person <nobody AT "
        + "example dot com>";
    private static ServerDescriptor createWithContactLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.contactLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String familyLine = null;
    private static ServerDescriptor createWithFamilyLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.familyLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String readHistoryLine = null;
    private static ServerDescriptor createWithReadHistoryLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.readHistoryLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String writeHistoryLine = null;
    private static ServerDescriptor createWithWriteHistoryLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.writeHistoryLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String eventdnsLine = null;
    private static ServerDescriptor createWithEventdnsLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.eventdnsLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String cachesExtraInfoLine = null;
    private static ServerDescriptor createWithCachesExtraInfoLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.cachesExtraInfoLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String extraInfoDigestLine = "opt extra-info-digest "
        + "1469D1550738A25B1E7B47CDDBCD7B2899F51B74";
    private static ServerDescriptor createWithExtraInfoDigestLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.extraInfoDigestLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String hiddenServiceDirLine = "opt hidden-service-dir";
    private static ServerDescriptor createWithHiddenServiceDirLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.hiddenServiceDirLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String protocolsLine = "opt protocols Link 1 2 Circuit 1";
    private static ServerDescriptor createWithProtocolsLine(
        String line) throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.protocolsLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String allowSingleHopExitsLine = null;
    private static ServerDescriptor
        createWithAllowSingleHopExitsLine(String line)
        throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.allowSingleHopExitsLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
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
      return new ServerDescriptorImpl(db.buildDescriptor(), true);
    }
    private String unrecognizedLine = null;
    private static ServerDescriptor createWithUnrecognizedLine(
        String line, boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.unrecognizedLine = line;
      return new ServerDescriptorImpl(db.buildDescriptor(),
          failUnrecognizedDescriptorLines);
    }
    private byte[] buildDescriptor() {
      StringBuilder sb = new StringBuilder();
      if (this.routerLine != null) {
        sb.append(this.routerLine + "\n");
      }
      if (this.bandwidthLine != null) {
        sb.append(this.bandwidthLine + "\n");
      }
      if (this.platformLine != null) {
        sb.append(this.platformLine + "\n");
      }
      if (this.publishedLine != null) {
        sb.append(this.publishedLine + "\n");
      }
      if (this.fingerprintLine != null) {
        sb.append(this.fingerprintLine + "\n");
      }
      if (this.hibernatingLine != null) {
        sb.append(this.hibernatingLine + "\n");
      }
      if (this.uptimeLine != null) {
        sb.append(this.uptimeLine + "\n");
      }
      if (this.onionKeyLines != null) {
        sb.append(this.onionKeyLines + "\n");
      }
      if (this.signingKeyLines != null) {
        sb.append(this.signingKeyLines + "\n");
      }
      if (this.exitPolicyLines != null) {
        sb.append(this.exitPolicyLines + "\n");
      }
      if (this.contactLine != null) {
        sb.append(this.contactLine + "\n");
      }
      if (this.familyLine != null) {
        sb.append(this.familyLine + "\n");
      }
      if (this.readHistoryLine != null) {
        sb.append(this.readHistoryLine + "\n");
      }
      if (this.writeHistoryLine != null) {
        sb.append(this.writeHistoryLine + "\n");
      }
      if (this.eventdnsLine != null) {
        sb.append(this.eventdnsLine + "\n");
      }
      if (this.cachesExtraInfoLine != null) {
        sb.append(this.cachesExtraInfoLine + "\n");
      }
      if (this.extraInfoDigestLine != null) {
        sb.append(this.extraInfoDigestLine + "\n");
      }
      if (this.hiddenServiceDirLine != null) {
        sb.append(this.hiddenServiceDirLine + "\n");
      }
      if (this.protocolsLine != null) {
        sb.append(this.protocolsLine + "\n");
      }
      if (this.allowSingleHopExitsLine != null) {
        sb.append(this.allowSingleHopExitsLine + "\n");
      }
      if (this.unrecognizedLine != null) {
        sb.append(this.unrecognizedLine + "\n");
      }
      if (this.routerSignatureLines != null) {
        sb.append(this.routerSignatureLines + "\n");
      }
      return sb.toString().getBytes();
    }
  }

  @Test()
  public void testSampleDescriptor() throws DescriptorParseException {
    DescriptorBuilder db = new DescriptorBuilder();
    ServerDescriptor descriptor =
        new ServerDescriptorImpl(db.buildDescriptor(), true);
    assertEquals("saberrider2008", descriptor.getNickname());
    assertEquals("94.134.192.243", descriptor.getAddress());
    assertEquals(9001, (int) descriptor.getOrPort());
    assertEquals(0, (int) descriptor.getSocksPort());
    assertEquals(0, (int) descriptor.getDirPort());
    assertEquals("Tor 0.2.2.35 (git-b04388f9e7546a9f) on Linux i686",
        descriptor.getPlatform());
    assertEquals(Arrays.asList(new Integer[] {1, 2}),
        descriptor.getLinkProtocolVersions());
    assertEquals(Arrays.asList(new Integer[] {1}),
        descriptor.getCircuitProtocolVersions());
    assertEquals(1325390599000L, descriptor.getPublishedMillis());
    assertEquals("D8733048FC8EC9102466AD8F3098622BF1BF71FD",
        descriptor.getFingerprint());
    assertEquals(48, (int) descriptor.getUptime());
    assertEquals(51200, (int) descriptor.getBandwidthRate());
    assertEquals(51200, (int) descriptor.getBandwidthBurst());
    assertEquals(53470, (int) descriptor.getBandwidthObserved());
    assertEquals("1469D1550738A25B1E7B47CDDBCD7B2899F51B74",
        descriptor.getExtraInfoDigest());
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithRouterLine("opt router saberrider2008 "
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithPlatformLine(null);
    assertNull(descriptor.getPlatform());
  }

  @Test()
  public void testPlatformOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithPlatformLine("opt platform Tor 0.2.2.35 "
        + "(git-b04388f9e7546a9f) on Linux i686");
    assertEquals("Tor 0.2.2.35 (git-b04388f9e7546a9f) on Linux i686",
        descriptor.getPlatform());
  }

  @Test()
  public void testPlatformNoSpace() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithPlatformLine("platform");
    assertEquals("", descriptor.getPlatform());
  }

  @Test()
  public void testPlatformSpace() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithPlatformLine("platform ");
    assertEquals("", descriptor.getPlatform());
  }

  @Test()
  public void testProtocolsNoOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithProtocolsLine("protocols Link 1 2 Circuit 1");
    assertEquals(Arrays.asList(new Integer[] {1, 2}),
        descriptor.getLinkProtocolVersions());
    assertEquals(Arrays.asList(new Integer[] {1}),
        descriptor.getCircuitProtocolVersions());
  }

  @Test(expected = DescriptorParseException.class)
  public void testProtocolsAB() throws DescriptorParseException {
    DescriptorBuilder.createWithProtocolsLine("opt protocols Link A B "
        + "Circuit 1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testProtocolsNoCircuitVersions()
      throws DescriptorParseException {
    DescriptorBuilder.createWithProtocolsLine("opt protocols Link 1 2");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublishedMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithPublishedLine(null);
  }

  @Test()
  public void testPublishedOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithPublishedLine("opt published 2012-01-01 04:03:19");
    assertEquals(1325390599000L, descriptor.getPublishedMillis());
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublished3012() throws DescriptorParseException {
    DescriptorBuilder.createWithPublishedLine("published 3012-01-01 "
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
  public void testFingerprintNoOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithFingerprintLine("fingerprint D873 3048 FC8E C910 2466 "
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithUptimeLine(null);
    assertEquals(-1, (int) descriptor.getUptime());
  }

  @Test()
  public void testUptimeOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithUptimeLine("opt uptime 48");
    assertEquals(48, (int) descriptor.getUptime());
  }

  @Test(expected = DescriptorParseException.class)
  public void testUptimeFourtyEight() throws DescriptorParseException {
    DescriptorBuilder.createWithUptimeLine("uptime fourty-eight");
  }

  @Test(expected = DescriptorParseException.class)
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithBandwidthLine("opt bandwidth 51200 51200 53470");
    assertEquals(51200, (int) descriptor.getBandwidthRate());
    assertEquals(51200, (int) descriptor.getBandwidthBurst());
    assertEquals(53470, (int) descriptor.getBandwidthObserved());
  }

  @Test(expected = DescriptorParseException.class)
  public void testBandwidthMissing() throws DescriptorParseException {
    DescriptorBuilder.createWithBandwidthLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testBandwidthTwoValues() throws DescriptorParseException {
    DescriptorBuilder.createWithBandwidthLine("bandwidth 51200 51200");
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithExtraInfoDigestLine("extra-info-digest "
        + "1469D1550738A25B1E7B47CDDBCD7B2899F51B74");
    assertEquals("1469D1550738A25B1E7B47CDDBCD7B2899F51B74",
        descriptor.getExtraInfoDigest());
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithExtraInfoDigestLine(null);
    assertNull(descriptor.getExtraInfoDigest());
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithHiddenServiceDirLine(null);
    assertNull(descriptor.getHiddenServiceDirVersions());
  }

  @Test()
  public void testHiddenServiceDirNoOpt()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithHiddenServiceDirLine("hidden-service-dir");
    assertEquals(Arrays.asList(new Integer[] {2}),
        descriptor.getHiddenServiceDirVersions());
  }

  @Test()
  public void testHiddenServiceDirVersions2And3()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithHiddenServiceDirLine("hidden-service-dir 2 3");
    assertEquals(Arrays.asList(new Integer[] {2, 3}),
        descriptor.getHiddenServiceDirVersions());
  }

  @Test()
  public void testContactMissing() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithContactLine(null);
    assertNull(descriptor.getContact());
  }

  @Test()
  public void testContactOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithContactLine("opt contact Random Person");
    assertEquals("Random Person", descriptor.getContact());
  }

  @Test(expected = DescriptorParseException.class)
  public void testContactDuplicate() throws DescriptorParseException {
    DescriptorBuilder.createWithContactLine("contact Random "
        + "Person\ncontact Random Person");
  }

  @Test()
  public void testContactNoSpace() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithContactLine("contact");
    assertEquals("", descriptor.getContact());
  }

  @Test()
  public void testExitPolicyRejectAllAcceptAll()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithExitPolicyLines("reject *:*\naccept *:*");
    assertEquals(Arrays.asList(new String[] {"reject *:*", "accept *:*"}),
        descriptor.getExitPolicyLines());
  }

  @Test()
  public void testExitPolicyOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithExitPolicyLines("opt reject *:*");
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithExitPolicyLines("accept *:80\nreject *:*");
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
  public void testRouterSignatureOpt()
      throws DescriptorParseException {
    DescriptorBuilder.createWithRouterSignatureLines("opt "
        + "router-signature\n"
        + "-----BEGIN SIGNATURE-----\n"
        + "crypto lines are ignored anyway\n"
        + "-----END SIGNATURE-----");
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithHibernatingLine("opt hibernating 1");
    assertTrue(descriptor.isHibernating());
  }

  @Test()
  public void testHibernatingFalse() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithHibernatingLine("hibernating 0");
    assertFalse(descriptor.isHibernating());
  }

  @Test()
  public void testHibernatingTrue() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithHibernatingLine("hibernating 1");
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithFamilyLine("opt family saberrider2008");
    assertEquals(Arrays.asList(new String[] {"saberrider2008"}),
        descriptor.getFamilyEntries());
  }

  @Test()
  public void testFamilyFingerprint() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithFamilyLine("family "
        + "$D8733048FC8EC9102466AD8F3098622BF1BF71FD");
    assertEquals(Arrays.asList(new String[] {
        "$D8733048FC8EC9102466AD8F3098622BF1BF71FD"}),
        descriptor.getFamilyEntries());
  }

  @Test()
  public void testFamilyNickname() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithFamilyLine("family saberrider2008");
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
  public void testFamilyFingerprintNickname()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithFamilyLine("family "
        + "$D8733048FC8EC9102466AD8F3098622BF1BF71FD=saberrider2008");
    assertEquals(Arrays.asList(new String[]
        { "$D8733048FC8EC9102466AD8F3098622BF1BF71FD=saberrider2008" }),
        descriptor.getFamilyEntries());
  }

  @Test()
  public void testWriteHistory() throws DescriptorParseException {
    String writeHistoryLine = "write-history 2012-01-01 03:51:44 (900 s) "
        + "4345856,261120,7591936,1748992";
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithWriteHistoryLine(writeHistoryLine);
    assertNotNull(descriptor.getWriteHistory());
    BandwidthHistory parsedWriteHistory = descriptor.getWriteHistory();
    assertEquals(writeHistoryLine, parsedWriteHistory.getLine());
    assertEquals(1325389904000L, (long) parsedWriteHistory.
        getHistoryEndMillis());
    assertEquals(900L, (long) parsedWriteHistory.getIntervalLength());
    SortedMap<Long, Long> bandwidthValues = parsedWriteHistory.
        getBandwidthValues();
    assertEquals(4345856L, (long) bandwidthValues.remove(1325387204000L));
    assertEquals(261120L, (long) bandwidthValues.remove(1325388104000L));
    assertEquals(7591936L, (long) bandwidthValues.remove(1325389004000L));
    assertEquals(1748992L, (long) bandwidthValues.remove(1325389904000L));
    assertTrue(bandwidthValues.isEmpty());
  }

  @Test()
  public void testWriteHistoryOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithWriteHistoryLine("opt write-history 2012-01-01 "
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithWriteHistoryLine("write-history 2012-01-01 03:51:44 "
        + "(900 s) ");
    assertEquals(900, (long) descriptor.getWriteHistory().
        getIntervalLength());
    assertTrue(descriptor.getWriteHistory().getBandwidthValues().
        isEmpty());
  }

  @Test()
  public void testWriteHistoryNoValuesNoSpace()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithWriteHistoryLine("write-history 2012-01-01 03:51:44 "
        + "(900 s)");
    assertEquals(900, (long) descriptor.getWriteHistory().
        getIntervalLength());
    assertTrue(descriptor.getWriteHistory().getBandwidthValues().
        isEmpty());
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryNoS() throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine(
        "write-history 2012-01-01 03:51:44 (900 ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testWriteHistoryTrailingNumber()
      throws DescriptorParseException {
    DescriptorBuilder.createWithWriteHistoryLine("write-history "
        + "2012-01-01 03:51:44 (900 s) 4345856 1");
  }

  @Test()
  public void testWriteHistory1800Seconds()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithWriteHistoryLine("write-history 2012-01-01 03:51:44 "
        + "(1800 s) 4345856");
    assertEquals(1800L, (long) descriptor.getWriteHistory().
        getIntervalLength());
  }

  @Test()
  public void testReadHistory() throws DescriptorParseException {
    String readHistoryLine = "read-history 2012-01-01 03:51:44 (900 s) "
        + "4268032,139264,7797760,1415168";
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithReadHistoryLine(readHistoryLine);
    assertNotNull(descriptor.getReadHistory());
    BandwidthHistory parsedReadHistory = descriptor.getReadHistory();
    assertEquals(readHistoryLine, parsedReadHistory.getLine());
    assertEquals(1325389904000L, (long) parsedReadHistory.
        getHistoryEndMillis());
    assertEquals(900L, (long) parsedReadHistory.getIntervalLength());
    SortedMap<Long, Long> bandwidthValues = parsedReadHistory.
        getBandwidthValues();
    assertEquals(4268032L, (long) bandwidthValues.remove(1325387204000L));
    assertEquals(139264L, (long) bandwidthValues.remove(1325388104000L));
    assertEquals(7797760L, (long) bandwidthValues.remove(1325389004000L));
    assertEquals(1415168L, (long) bandwidthValues.remove(1325389904000L));
    assertTrue(bandwidthValues.isEmpty());
  }

  /* TODO There are some old server descriptors with "read-history  "
   * lines.  Find out if these were spec-compliant and if other lines may
   * start with leading spaces, too. */
  @Test(expected = DescriptorParseException.class)
  public void testReadHistoryLeadingSpace()
      throws DescriptorParseException {
    String readHistoryLine = "read-history  2012-01-01 03:51:44 (900 s) "
        + "4268032,139264,7797760,1415168";
    DescriptorBuilder.createWithReadHistoryLine(readHistoryLine);
  }

  @Test()
  public void testEventdnsOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithEventdnsLine("opt eventdns 1");
    assertTrue(descriptor.getUsesEnhancedDnsLogic());
  }

  @Test()
  public void testEventdnsTrue() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithEventdnsLine("eventdns 1");
    assertTrue(descriptor.getUsesEnhancedDnsLogic());
  }

  @Test()
  public void testEventdnsFalse() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithEventdnsLine("eventdns 0");
    assertFalse(descriptor.getUsesEnhancedDnsLogic());
  }

  @Test(expected = DescriptorParseException.class)
  public void testEventdns1() throws DescriptorParseException {
    DescriptorBuilder.createWithEventdnsLine("eventdns true");
  }

  @Test(expected = DescriptorParseException.class)
  public void testEventdnsNo() throws DescriptorParseException {
    DescriptorBuilder.createWithEventdnsLine("eventdns no");
  }

  @Test()
  public void testCachesExtraInfoOpt() throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithCachesExtraInfoLine("opt caches-extra-info");
    assertTrue(descriptor.getCachesExtraInfo());
  }

  @Test()
  public void testCachesExtraInfoNoSpace()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithCachesExtraInfoLine("caches-extra-info");
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithAllowSingleHopExitsLine("opt allow-single-hop-exits");
    assertTrue(descriptor.getAllowSingleHopExits());
  }

  @Test()
  public void testAllowSingleHopExitsNoSpace()
      throws DescriptorParseException {
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithAllowSingleHopExitsLine("allow-single-hop-exits");
    assertTrue(descriptor.getAllowSingleHopExits());
  }

  @Test(expected = DescriptorParseException.class)
  public void testAllowSingleHopExitsTrue()
      throws DescriptorParseException {
    DescriptorBuilder.createWithAllowSingleHopExitsLine(
        "allow-single-hop-exits true");
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
    ServerDescriptor descriptor = DescriptorBuilder.
        createWithUnrecognizedLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<String>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, descriptor.getUnrecognizedLines());
  }
}

