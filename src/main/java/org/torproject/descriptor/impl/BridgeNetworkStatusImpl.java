/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Map;
import java.util.Scanner;
import java.util.SortedMap;
import java.util.TimeZone;

import org.torproject.descriptor.BridgeNetworkStatus;

/* Contains a bridge network status. */
public class BridgeNetworkStatusImpl extends NetworkStatusImpl
    implements BridgeNetworkStatus {

  protected BridgeNetworkStatusImpl(byte[] statusBytes,
      String fileName, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(statusBytes, failUnrecognizedDescriptorLines, false, false);
    this.setPublishedMillisFromFileName(fileName);
  }

  private void setPublishedMillisFromFileName(String fileName)
      throws DescriptorParseException {
    if (this.publishedMillis != 0L) {
      /* We already learned the publication timestamp from parsing the
       * "published" line. */
      return;
    }
    if (fileName.length() ==
        "20000101-000000-4A0CCD2DDC7995083D73F5D667100C8A5831F16D".
        length()) {
      String publishedString = fileName.substring(0,
          "yyyyMMdd-HHmmss".length());
      try {
        SimpleDateFormat fileNameFormat = new SimpleDateFormat(
            "yyyyMMdd-HHmmss");
        fileNameFormat.setLenient(false);
        fileNameFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        this.publishedMillis = fileNameFormat.parse(publishedString).
            getTime();
      } catch (ParseException e) {
      }
    }
    if (this.publishedMillis == 0L) {
      throw new DescriptorParseException("Unrecognized bridge network "
          + "status file name '" + fileName + "'.");
    }
  }

  protected void parseHeader(byte[] headerBytes)
      throws DescriptorParseException {
    /* Initialize flag-thresholds values here for the case that the status
     * doesn't contain those values.  Initializing them in the constructor
     * or when declaring variables wouldn't work, because those parts are
     * evaluated later and would overwrite everything we parse here. */
    this.stableUptime = -1L;
    this.stableMtbf = -1L;
    this.fastBandwidth = -1L;
    this.guardWfu = -1.0;
    this.guardTk = -1L;
    this.guardBandwidthIncludingExits = -1L;
    this.guardBandwidthExcludingExits = -1L;
    this.enoughMtbfInfo = -1;
    this.ignoringAdvertisedBws = -1;

    Scanner s = new Scanner(new String(headerBytes)).useDelimiter("\n");
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split("[ \t]+");
      String keyword = parts[0];
      switch (keyword) {
      case "published":
        this.parsePublishedLine(line, parts);
        break;
      case "flag-thresholds":
        this.parseFlagThresholdsLine(line, parts);
        break;
      default:
        if (this.failUnrecognizedDescriptorLines) {
          throw new DescriptorParseException("Unrecognized line '" + line
              + "' in bridge network status.");
        } else {
          if (this.unrecognizedLines == null) {
            this.unrecognizedLines = new ArrayList<>();
          }
          this.unrecognizedLines.add(line);
        }
      }
    }
  }

  private void parsePublishedLine(String line, String[] parts)
      throws DescriptorParseException {
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseFlagThresholdsLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 2) {
      throw new DescriptorParseException("No flag thresholds in line '"
          + line + "'.");
    }
    SortedMap<String, String> flagThresholds =
        ParseHelper.parseKeyValueStringPairs(line, parts, 1, "=");
    try {
      for (Map.Entry<String, String> e : flagThresholds.entrySet()) {
        switch (e.getKey()) {
        case "stable-uptime":
          this.stableUptime = Long.parseLong(e.getValue());
          break;
        case "stable-mtbf":
          this.stableMtbf = Long.parseLong(e.getValue());
          break;
        case "fast-speed":
          this.fastBandwidth = Long.parseLong(e.getValue());
          break;
        case "guard-wfu":
          this.guardWfu = Double.parseDouble(e.getValue().
              replaceAll("%", ""));
          break;
        case "guard-tk":
          this.guardTk = Long.parseLong(e.getValue());
          break;
        case "guard-bw-inc-exits":
          this.guardBandwidthIncludingExits =
              Long.parseLong(e.getValue());
          break;
        case "guard-bw-exc-exits":
          this.guardBandwidthExcludingExits =
              Long.parseLong(e.getValue());
          break;
        case "enough-mtbf":
          this.enoughMtbfInfo = Integer.parseInt(e.getValue());
          break;
        case "ignoring-advertised-bws":
          this.ignoringAdvertisedBws = Integer.parseInt(e.getValue());
          break;
        }
      }
    } catch (NumberFormatException ex) {
      throw new DescriptorParseException("Illegal value in line '"
          + line + "'.");
    }
  }

  protected void parseDirSource(byte[] dirSourceBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory source expected in "
        + "bridge network status.");
  }

  protected void parseFooter(byte[] footerBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory footer expected in "
        + "bridge network status.");
  }

  protected void parseDirectorySignature(byte[] directorySignatureBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory signature expected "
        + "in bridge network status.");
  }

  private long publishedMillis;
  @Override
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private long stableUptime;
  @Override
  public long getStableUptime() {
    return this.stableUptime;
  }

  private long stableMtbf;
  @Override
  public long getStableMtbf() {
    return this.stableMtbf;
  }

  private long fastBandwidth;
  @Override
  public long getFastBandwidth() {
    return this.fastBandwidth;
  }

  private double guardWfu;
  @Override
  public double getGuardWfu() {
    return this.guardWfu;
  }

  private long guardTk;
  @Override
  public long getGuardTk() {
    return this.guardTk;
  }

  private long guardBandwidthIncludingExits;
  @Override
  public long getGuardBandwidthIncludingExits() {
    return this.guardBandwidthIncludingExits;
  }

  private long guardBandwidthExcludingExits;
  @Override
  public long getGuardBandwidthExcludingExits() {
    return this.guardBandwidthExcludingExits;
  }

  private int enoughMtbfInfo;
  @Override
  public int getEnoughMtbfInfo() {
    return this.enoughMtbfInfo;
  }

  private int ignoringAdvertisedBws;
  @Override
  public int getIgnoringAdvertisedBws() {
    return this.ignoringAdvertisedBws;
  }
}

