/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.descriptor.DescriptorParseException;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/* Test parsing of bridge network statuses.  Some of the parsing code is
 * already tested in the consensus/vote-parsing tests. */
public class BridgeNetworkStatusTest {

  /* Helper class to build a bridge network status based on default data
   * and modifications requested by test methods. */
  private static class StatusBuilder {

    private String fileName = "20151121-173936-"
        + "4A0CCD2DDC7995083D73F5D667100C8A5831F16D";

    private static BridgeNetworkStatus
        createWithFileName(String fileName)
        throws DescriptorParseException {
      StatusBuilder sb = new StatusBuilder();
      sb.fileName = fileName;
      return sb.buildStatus(true);
    }

    private String publishedLine = "published 2015-11-21 17:39:36";

    private static BridgeNetworkStatus
        createWithPublishedLine(String line)
        throws DescriptorParseException {
      StatusBuilder sb = new StatusBuilder();
      sb.publishedLine = line;
      return sb.buildStatus(true);
    }

    private String flagThresholdsLine = "flag-thresholds "
        + "stable-uptime=3105080 stable-mtbf=2450615 fast-speed=55000 "
        + "guard-wfu=98.000% guard-tk=691200 guard-bw-inc-exits=337000 "
        + "guard-bw-exc-exits=339000 enough-mtbf=1 "
        + "ignoring-advertised-bws=0";

    private static BridgeNetworkStatus
        createWithFlagThresholdsLine(String line)
        throws DescriptorParseException {
      StatusBuilder sb = new StatusBuilder();
      sb.flagThresholdsLine = line;
      return sb.buildStatus(true);
    }

    private List<String> statusEntries = new ArrayList<>();

    private String unrecognizedHeaderLine = null;

    protected static BridgeNetworkStatus
        createWithUnrecognizedHeaderLine(String line,
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      StatusBuilder sb = new StatusBuilder();
      sb.unrecognizedHeaderLine = line;
      return sb.buildStatus(failUnrecognizedDescriptorLines);
    }

    private String unrecognizedStatusEntryLine = null;

    protected static BridgeNetworkStatus
        createWithUnrecognizedStatusEntryLine(String line,
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      StatusBuilder sb = new StatusBuilder();
      sb.unrecognizedStatusEntryLine = line;
      return sb.buildStatus(failUnrecognizedDescriptorLines);
    }

    private StatusBuilder() {
      this.statusEntries.add("r Unnamed ABk0wg4j6BLCdZKleVtmNrfzJGI "
          + "bh7gVU1Cz6+JG+7j4qGsF4prDi8 2015-11-21 15:46:25 "
          + "10.153.163.200 443 0\ns Fast Running Stable Valid\n"
          + "w Bandwidth=264\np reject 1-65535");
    }

    private byte[] buildStatusBytes() {
      StringBuilder sb = new StringBuilder();
      this.appendHeader(sb);
      this.appendStatusEntries(sb);
      return sb.toString().getBytes();
    }

    private BridgeNetworkStatus buildStatus(
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      byte[] statusBytes = this.buildStatusBytes();
      return new BridgeNetworkStatusImpl(statusBytes,
          new int[] { 0, statusBytes.length }, null, this.fileName,
          failUnrecognizedDescriptorLines);
    }

    private void appendHeader(StringBuilder sb) {
      if (this.publishedLine != null) {
        sb.append(this.publishedLine).append("\n");
      }
      if (this.flagThresholdsLine != null) {
        sb.append(this.flagThresholdsLine).append("\n");
      }
      if (this.unrecognizedHeaderLine != null) {
        sb.append(this.unrecognizedHeaderLine).append("\n");
      }
    }

    private void appendStatusEntries(StringBuilder sb) {
      for (String statusEntry : this.statusEntries) {
        sb.append(statusEntry).append("\n");
      }
      if (this.unrecognizedStatusEntryLine != null) {
        sb.append(this.unrecognizedStatusEntryLine).append("\n");
      }
    }
  }

  @Test
  public void testSampleStatus() throws DescriptorParseException {
    StatusBuilder sb = new StatusBuilder();
    BridgeNetworkStatus status = sb.buildStatus(true);
    assertEquals(1448127576000L, status.getPublishedMillis());
    assertEquals(3105080L, status.getStableUptime());
    assertEquals(2450615L, status.getStableMtbf());
    assertEquals(55000L, status.getFastBandwidth());
    assertEquals(98.0, status.getGuardWfu(), 0.001);
    assertEquals(691200L, status.getGuardTk());
    assertEquals(337000L, status.getGuardBandwidthIncludingExits());
    assertEquals(339000L, status.getGuardBandwidthExcludingExits());
    assertEquals(1, status.getEnoughMtbfInfo());
    assertEquals(0, status.getIgnoringAdvertisedBws());
    assertEquals(264, status.getStatusEntries().get(
        "001934C20E23E812C27592A5795B6636B7F32462").getBandwidth());
    assertTrue(status.getUnrecognizedLines().isEmpty());
  }

  @Test
  public void testPublishedNoLine() throws DescriptorParseException {
    BridgeNetworkStatus status =
        StatusBuilder.createWithPublishedLine(null);
    assertEquals(1448127576000L, status.getPublishedMillis());
  }

  @Test
  public void testFlagThresholdsNoLine() throws DescriptorParseException {
    BridgeNetworkStatus status =
        StatusBuilder.createWithFlagThresholdsLine(null);
    assertEquals(-1L, status.getStableUptime());
    assertEquals(-1L, status.getStableMtbf());
    assertEquals(-1L, status.getFastBandwidth());
    assertEquals(-1.0, status.getGuardWfu(), 0.001);
    assertEquals(-1L, status.getGuardTk());
    assertEquals(-1L, status.getGuardBandwidthIncludingExits());
    assertEquals(-1L, status.getGuardBandwidthExcludingExits());
    assertEquals(-1, status.getEnoughMtbfInfo());
    assertEquals(-1, status.getIgnoringAdvertisedBws());
  }
}

