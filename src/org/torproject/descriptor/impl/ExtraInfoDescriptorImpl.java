/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;

import org.torproject.descriptor.BandwidthHistory;
import org.torproject.descriptor.ExtraInfoDescriptor;

/* TODO Implement methods to parse the various statistics (other than
 * bandwidth histories. */
/* TODO Write a test class. */
public class ExtraInfoDescriptorImpl extends DescriptorImpl
    implements ExtraInfoDescriptor {

  protected static List<ExtraInfoDescriptor> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<ExtraInfoDescriptor> parsedDescriptors =
        new ArrayList<ExtraInfoDescriptor>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "extra-info ");
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      ExtraInfoDescriptor parsedDescriptor =
          new ExtraInfoDescriptorImpl(descriptorBytes,
              failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected ExtraInfoDescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines);
    this.parseDescriptorBytes();
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList((
        "extra-info,published").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList((
        "read-history,write-history,geoip-db-digest,dirreq-stats-end,"
        + "dirreq-v2-ips,dirreq-v3-ips,dirreq-v2-reqs,dirreq-v3-reqs,"
        + "dirreq-v2-share,dirreq-v3-share,dirreq-v2-resp,dirreq-v3-resp,"
        + "dirreq-v2-direct-dl,dirreq-v3-direct-dl,dirreq-v2-tunneled-dl,"
        + "dirreq-v3-tunneled-dl,dirreq-read-history,"
        + "dirreq-write-history,entry-stats-end,entry-ips,cell-stats-end,"
        + "cell-processed-cells,cell-queued-cells,cell-time-in-queue,"
        + "cell-circuits-per-decile,conn-bi-direct,exit-stats-end,"
        + "exit-kibibytes-written,exit-kibibytes-read,"
        + "exit-streams-opened,bridge-stats-end,bridge-stats-ips,"
        + "router-signature").split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    /* TODO Add more checks to see that only statistics details lines are
     * included with corresponding statistics interval lines. */
    this.checkFirstKeyword("extra-info");
    return;
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.rawDescriptorBytes)));
      String line;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {
        String lineNoOpt = line.startsWith("opt ") ?
            line.substring("opt ".length()) : line;
        String[] partsNoOpt = lineNoOpt.split(" ");
        String keyword = partsNoOpt[0];
        if (keyword.equals("extra-info")) {
          this.parseExtraInfoLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("published")) {
          this.parsePublishedLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("read-history")) {
          this.parseReadHistoryLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("write-history")) {
          this.parseWriteHistoryLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("geoip-db-digest")) {
          this.parseGeoipDbDigestLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("geoip-start-time")) {
          this.parseGeoipStartTimeLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("geoip-client-origins")) {
          this.parseGeoipClientOriginsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-stats-end")) {
          this.parseDirreqStatsEndLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v2-ips")) {
          this.parseDirreqV2IpsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v3-ips")) {
          this.parseDirreqV3IpsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v2-reqs")) {
          this.parseDirreqV2ReqsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v3-reqs")) {
          this.parseDirreqV3ReqsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v2-share")) {
          this.parseDirreqV2ShareLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v3-share")) {
          this.parseDirreqV3ShareLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v2-resp")) {
          this.parseDirreqV2RespLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v3-resp")) {
          this.parseDirreqV3RespLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v2-direct-dl")) {
          this.parseDirreqV2DirectDlLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v3-direct-dl")) {
          this.parseDirreqV3DirectDlLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v2-tunneled-dl")) {
          this.parseDirreqV2TunneledDlLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-v3-tunneled-dl")) {
          this.parseDirreqV3TunneledDlLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-read-history")) {
          this.parseDirreqReadHistoryLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("dirreq-write-history")) {
          this.parseDirreqWriteHistoryLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("entry-stats-end")) {
          this.parseEntryStatsEndLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("entry-ips")) {
          this.parseEntryIpsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("cell-stats-end")) {
          this.parseCellStatsEndLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("cell-processed-cells")) {
          this.parseCellProcessedCellsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("cell-queued-cells")) {
          this.parseCellQueuedCellsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("cell-time-in-queue")) {
          this.parseCellTimeInQueueLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("cell-circuits-per-decile")) {
          this.parseCellCircuitsPerDecileLine(line, lineNoOpt,
              partsNoOpt);
        } else if (keyword.equals("conn-bi-direct")) {
          this.parseConnBiDirectLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("exit-stats-end")) {
          this.parseExitStatsEndLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("exit-kibibytes-written")) {
          this.parseExitKibibytesWrittenLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("exit-kibibytes-read")) {
          this.parseExitKibibytesReadLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("exit-streams-opened")) {
          this.parseExitStreamsOpenedLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("bridge-stats-end")) {
          this.parseBridgeStatsEndLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("bridge-ips")) {
          this.parseBridgeStatsIpsLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("router-signature")) {
          this.parseRouterSignatureLine(line, lineNoOpt, partsNoOpt);
        } else if (line.startsWith("-----BEGIN")) {
          skipCrypto = true;
        } else if (line.startsWith("-----END")) {
          skipCrypto = false;
        } else if (!skipCrypto) {
          if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized line '"
                + line + "' in extra-info descriptor.");
          } else {
            if (this.unrecognizedLines == null) {
              this.unrecognizedLines = new ArrayList<String>();
            }
            this.unrecognizedLines.add(line);
          }
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  private void parseExtraInfoLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 3) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in extra-info descriptor.");
    }
    this.nickname = ParseHelper.parseNickname(line, partsNoOpt[1]);
    this.fingerprint = ParseHelper.parseTwentyByteHexString(line,
        partsNoOpt[2]);
  }

  private void parsePublishedLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line,
        partsNoOpt, 1, 2);
  }

  private void parseReadHistoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.readHistory = new BandwidthHistoryImpl(line, lineNoOpt,
        partsNoOpt);
  }

  private void parseWriteHistoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.writeHistory = new BandwidthHistoryImpl(line, lineNoOpt,
        partsNoOpt);
  }

  private void parseGeoipDbDigestLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseGeoipStartTimeLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseGeoipClientOriginsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV2IpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV3IpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV2ReqsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV3ReqsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV2ShareLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV3ShareLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV2RespLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV3RespLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV2DirectDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV3DirectDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV2TunneledDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqV3TunneledDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseDirreqReadHistoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqReadHistory = new BandwidthHistoryImpl(line, lineNoOpt,
        partsNoOpt);
  }

  private void parseDirreqWriteHistoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqWriteHistory = new BandwidthHistoryImpl(line, lineNoOpt,
        partsNoOpt);
  }

  private void parseEntryStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseEntryIpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseCellStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseCellProcessedCellsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseCellQueuedCellsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseCellTimeInQueueLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseCellCircuitsPerDecileLine(String line,
      String lineNoOpt, String[] partsNoOpt)
      throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseConnBiDirectLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseExitStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseExitKibibytesWrittenLine(String line,
      String lineNoOpt, String[] partsNoOpt)
      throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseExitKibibytesReadLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseExitStreamsOpenedLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseBridgeStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseBridgeStatsIpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* TODO Implement me. */
  }

  private void parseRouterSignatureLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("router-signature")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    /* Not parsing crypto parts (yet). */
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private BandwidthHistory readHistory;
  public BandwidthHistory getReadHistory() {
    return this.readHistory;
  }

  private BandwidthHistory writeHistory;
  public BandwidthHistory getWriteHistory() {
    return this.writeHistory;
  }

  public String getGeoipDbDigest() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getDirreqStatsEndMillis() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getDirreqStatsIntervalLength() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV2Ips() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV3Ips() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV2Reqs() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV3Reqs() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public double getDirreqV2Share() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public double getDirreqV3Share() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV2Resp() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV3Resp() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV2DirectDl() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV3DirectDl() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV2TunneledDl() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getDirreqV3TunneledDl() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  private BandwidthHistory dirreqReadHistory;
  public BandwidthHistory getDirreqReadHistory() {
    return this.dirreqReadHistory;
  }

  private BandwidthHistory dirreqWriteHistory;
  public BandwidthHistory getDirreqWriteHistory() {
    return this.dirreqWriteHistory;
  }

  public long getEntryStatsEndMillis() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getEntryStatsIntervalLength() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<String, Integer> getEntryIps() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getCellStatsEndMillis() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getCellStatsIntervalLength() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public List<Integer> getCellProcessedCells() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public List<Integer> getCellQueueCells() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public List<Integer> getCellTimeInQueue() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public int getCellCircuitsPerDecile() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getConnBiDirectStatsEndMillis() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getConnBiDirectIntervalLength() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public int getConnBiDirectBelow() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public int getConnBiDirectRead() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public int getConnBiDirectWrite() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public int getConnBiDirectBoth() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getExitStatsEndMillis() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public long getExitStatsIntervalLength() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<Integer, Integer> getExitKibibytesWritten() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<Integer, Integer> getExitKibibytesRead() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }

  public SortedMap<Integer, Integer> getExitStreamsOpened() {
    /* TODO Implement me. */
    throw new UnsupportedOperationException();
  }
}

