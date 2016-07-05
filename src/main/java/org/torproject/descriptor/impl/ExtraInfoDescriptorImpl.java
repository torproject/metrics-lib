/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.BandwidthHistory;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ExtraInfoDescriptor;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.xml.bind.DatatypeConverter;

public abstract class ExtraInfoDescriptorImpl extends DescriptorImpl
    implements ExtraInfoDescriptor {

  protected ExtraInfoDescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseDescriptorBytes();
    this.calculateDigest();
    this.calculateDigestSha256();
    Set<String> exactlyOnceKeywords = new HashSet<>(Arrays.asList((
        "extra-info,published").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> dirreqStatsKeywords = new HashSet<>(Arrays.asList((
        "dirreq-stats-end,dirreq-v2-ips,dirreq-v3-ips,dirreq-v2-reqs,"
        + "dirreq-v3-reqs,dirreq-v2-share,dirreq-v3-share,dirreq-v2-resp,"
        + "dirreq-v3-resp,dirreq-v2-direct-dl,dirreq-v3-direct-dl,"
        + "dirreq-v2-tunneled-dl,dirreq-v3-tunneled-dl,").split(",")));
    Set<String> entryStatsKeywords = new HashSet<>(Arrays.asList(
        "entry-stats-end,entry-ips".split(",")));
    Set<String> cellStatsKeywords = new HashSet<>(Arrays.asList((
        "cell-stats-end,cell-processed-cells,cell-queued-cells,"
        + "cell-time-in-queue,cell-circuits-per-decile").split(",")));
    Set<String> connBiDirectStatsKeywords = new HashSet<>(
        Arrays.asList("conn-bi-direct".split(",")));
    Set<String> exitStatsKeywords = new HashSet<>(Arrays.asList((
        "exit-stats-end,exit-kibibytes-written,exit-kibibytes-read,"
        + "exit-streams-opened").split(",")));
    Set<String> bridgeStatsKeywords = new HashSet<>(Arrays.asList(
        "bridge-stats-end,bridge-stats-ips".split(",")));
    Set<String> atMostOnceKeywords = new HashSet<>(Arrays.asList((
        "identity-ed25519,master-key-ed25519,read-history,write-history,"
        + "dirreq-read-history,dirreq-write-history,geoip-db-digest,"
        + "router-sig-ed25519,router-signature,router-digest-sha256,"
        + "router-digest").split(",")));
    atMostOnceKeywords.addAll(dirreqStatsKeywords);
    atMostOnceKeywords.addAll(entryStatsKeywords);
    atMostOnceKeywords.addAll(cellStatsKeywords);
    atMostOnceKeywords.addAll(connBiDirectStatsKeywords);
    atMostOnceKeywords.addAll(exitStatsKeywords);
    atMostOnceKeywords.addAll(bridgeStatsKeywords);
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkKeywordsDependOn(dirreqStatsKeywords, "dirreq-stats-end");
    this.checkKeywordsDependOn(entryStatsKeywords, "entry-stats-end");
    this.checkKeywordsDependOn(cellStatsKeywords, "cell-stats-end");
    this.checkKeywordsDependOn(exitStatsKeywords, "exit-stats-end");
    this.checkKeywordsDependOn(bridgeStatsKeywords, "bridge-stats-end");
    this.checkFirstKeyword("extra-info");
    this.clearParsedKeywords();
    return;
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.rawDescriptorBytes))
        .useDelimiter("\n");
    String nextCrypto = "";
    List<String> cryptoLines = null;
    while (s.hasNext()) {
      String line = s.next();
      String lineNoOpt = line.startsWith("opt ")
          ? line.substring("opt ".length()) : line;
      String[] partsNoOpt = lineNoOpt.split("[ \t]+");
      String keyword = partsNoOpt[0];
      switch (keyword) {
        case "extra-info":
          this.parseExtraInfoLine(line, lineNoOpt, partsNoOpt);
          break;
        case "published":
          this.parsePublishedLine(line, lineNoOpt, partsNoOpt);
          break;
        case "read-history":
          this.parseReadHistoryLine(line, lineNoOpt, partsNoOpt);
          break;
        case "write-history":
          this.parseWriteHistoryLine(line, lineNoOpt, partsNoOpt);
          break;
        case "geoip-db-digest":
          this.parseGeoipDbDigestLine(line, lineNoOpt, partsNoOpt);
          break;
        case "geoip6-db-digest":
          this.parseGeoip6DbDigestLine(line, lineNoOpt, partsNoOpt);
          break;
        case "geoip-start-time":
          this.parseGeoipStartTimeLine(line, lineNoOpt, partsNoOpt);
          break;
        case "geoip-client-origins":
          this.parseGeoipClientOriginsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-stats-end":
          this.parseDirreqStatsEndLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v2-ips":
          this.parseDirreqV2IpsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v3-ips":
          this.parseDirreqV3IpsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v2-reqs":
          this.parseDirreqV2ReqsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v3-reqs":
          this.parseDirreqV3ReqsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v2-share":
          this.parseDirreqV2ShareLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v3-share":
          this.parseDirreqV3ShareLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v2-resp":
          this.parseDirreqV2RespLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v3-resp":
          this.parseDirreqV3RespLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v2-direct-dl":
          this.parseDirreqV2DirectDlLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v3-direct-dl":
          this.parseDirreqV3DirectDlLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v2-tunneled-dl":
          this.parseDirreqV2TunneledDlLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-v3-tunneled-dl":
          this.parseDirreqV3TunneledDlLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-read-history":
          this.parseDirreqReadHistoryLine(line, lineNoOpt, partsNoOpt);
          break;
        case "dirreq-write-history":
          this.parseDirreqWriteHistoryLine(line, lineNoOpt, partsNoOpt);
          break;
        case "entry-stats-end":
          this.parseEntryStatsEndLine(line, lineNoOpt, partsNoOpt);
          break;
        case "entry-ips":
          this.parseEntryIpsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "cell-stats-end":
          this.parseCellStatsEndLine(line, lineNoOpt, partsNoOpt);
          break;
        case "cell-processed-cells":
          this.parseCellProcessedCellsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "cell-queued-cells":
          this.parseCellQueuedCellsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "cell-time-in-queue":
          this.parseCellTimeInQueueLine(line, lineNoOpt, partsNoOpt);
          break;
        case "cell-circuits-per-decile":
          this.parseCellCircuitsPerDecileLine(line, lineNoOpt,
              partsNoOpt);
          break;
        case "conn-bi-direct":
          this.parseConnBiDirectLine(line, lineNoOpt, partsNoOpt);
          break;
        case "exit-stats-end":
          this.parseExitStatsEndLine(line, lineNoOpt, partsNoOpt);
          break;
        case "exit-kibibytes-written":
          this.parseExitKibibytesWrittenLine(line, lineNoOpt, partsNoOpt);
          break;
        case "exit-kibibytes-read":
          this.parseExitKibibytesReadLine(line, lineNoOpt, partsNoOpt);
          break;
        case "exit-streams-opened":
          this.parseExitStreamsOpenedLine(line, lineNoOpt, partsNoOpt);
          break;
        case "bridge-stats-end":
          this.parseBridgeStatsEndLine(line, lineNoOpt, partsNoOpt);
          break;
        case "bridge-ips":
          this.parseBridgeStatsIpsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "bridge-ip-versions":
          this.parseBridgeIpVersionsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "bridge-ip-transports":
          this.parseBridgeIpTransportsLine(line, lineNoOpt, partsNoOpt);
          break;
        case "transport":
          this.parseTransportLine(line, lineNoOpt, partsNoOpt);
          break;
        case "hidserv-stats-end":
          this.parseHidservStatsEndLine(line, lineNoOpt, partsNoOpt);
          break;
        case "hidserv-rend-relayed-cells":
          this.parseHidservRendRelayedCellsLine(line, lineNoOpt,
              partsNoOpt);
          break;
        case "hidserv-dir-onions-seen":
          this.parseHidservDirOnionsSeenLine(line, lineNoOpt, partsNoOpt);
          break;
        case "identity-ed25519":
          this.parseIdentityEd25519Line(line, lineNoOpt, partsNoOpt);
          nextCrypto = "identity-ed25519";
          break;
        case "master-key-ed25519":
          this.parseMasterKeyEd25519Line(line, lineNoOpt, partsNoOpt);
          break;
        case "router-sig-ed25519":
          this.parseRouterSigEd25519Line(line, lineNoOpt, partsNoOpt);
          break;
        case "router-signature":
          this.parseRouterSignatureLine(line, lineNoOpt, partsNoOpt);
          nextCrypto = "router-signature";
          break;
        case "router-digest":
          this.parseRouterDigestLine(line, lineNoOpt, partsNoOpt);
          break;
        case "router-digest-sha256":
          this.parseRouterDigestSha256Line(line, lineNoOpt, partsNoOpt);
          break;
        case "-----BEGIN":
          cryptoLines = new ArrayList<>();
          cryptoLines.add(line);
          break;
        case "-----END":
          cryptoLines.add(line);
          StringBuilder sb = new StringBuilder();
          for (String cryptoLine : cryptoLines) {
            sb.append("\n").append(cryptoLine);
          }
          String cryptoString = sb.toString().substring(1);
          switch (nextCrypto) {
            case "router-signature":
              this.routerSignature = cryptoString;
              break;
            case "identity-ed25519":
              this.identityEd25519 = cryptoString;
              this.parseIdentityEd25519CryptoBlock(cryptoString);
              break;
            default:
              if (this.failUnrecognizedDescriptorLines) {
                throw new DescriptorParseException("Unrecognized crypto "
                    + "block '" + cryptoString + "' in extra-info "
                    + "descriptor.");
              } else {
                if (this.unrecognizedLines == null) {
                  this.unrecognizedLines = new ArrayList<>();
                }
                this.unrecognizedLines.addAll(cryptoLines);
              }
              cryptoLines = null;
              nextCrypto = "";
          }
          break;
        default:
          if (cryptoLines != null) {
            cryptoLines.add(line);
          } else {
            ParseHelper.parseKeyword(line, partsNoOpt[0]);
            if (this.failUnrecognizedDescriptorLines) {
              throw new DescriptorParseException("Unrecognized line '"
                  + line + "' in extra-info descriptor.");
            } else {
              if (this.unrecognizedLines == null) {
                this.unrecognizedLines = new ArrayList<>();
              }
              this.unrecognizedLines.add(line);
            }
          }
      }
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
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in extra-info descriptor.");
    }
    this.geoipDbDigest = ParseHelper.parseTwentyByteHexString(line,
        partsNoOpt[1]);
  }

  private void parseGeoip6DbDigestLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in extra-info descriptor.");
    }
    this.geoip6DbDigest = ParseHelper.parseTwentyByteHexString(line,
        partsNoOpt[1]);
  }

  private void parseGeoipStartTimeLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 3) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in extra-info descriptor.");
    }
    this.geoipStartTimeMillis = ParseHelper.parseTimestampAtIndex(line,
        partsNoOpt, 1, 2);
  }

  private void parseGeoipClientOriginsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.geoipClientOrigins =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 2);
  }

  private void parseDirreqStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    long[] parsedStatsEndData = this.parseStatsEndLine(line, partsNoOpt,
        5);
    this.dirreqStatsEndMillis = parsedStatsEndData[0];
    this.dirreqStatsIntervalLength = parsedStatsEndData[1];
  }

  private long[] parseStatsEndLine(String line, String[] partsNoOpt,
      int partsNoOptExpectedLength) throws DescriptorParseException {
    if (partsNoOpt.length != partsNoOptExpectedLength
        || partsNoOpt[3].length() < 2 || !partsNoOpt[3].startsWith("(")
        || !partsNoOpt[4].equals("s)")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    long[] result = new long[2];
    result[0] = ParseHelper.parseTimestampAtIndex(line, partsNoOpt, 1, 2);
    result[1] = ParseHelper.parseSeconds(line,
        partsNoOpt[3].substring(1));
    if (result[1] <= 0) {
      throw new DescriptorParseException("Interval length must be "
          + "positive in line '" + line + "'.");
    }
    return result;
  }

  private void parseDirreqV2IpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV2Ips = ParseHelper.parseCommaSeparatedKeyIntegerValueList(
        line, partsNoOpt, 1, 2);
  }

  private void parseDirreqV3IpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV3Ips = ParseHelper.parseCommaSeparatedKeyIntegerValueList(
        line, partsNoOpt, 1, 2);
  }

  private void parseDirreqV2ReqsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV2Reqs =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 2);
  }

  private void parseDirreqV3ReqsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV3Reqs =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 2);
  }

  private void parseDirreqV2ShareLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV2Share = this.parseShareLine(line, partsNoOpt);
  }

  private void parseDirreqV3ShareLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV3Share = this.parseShareLine(line, partsNoOpt);
  }

  private double parseShareLine(String line, String[] partsNoOpt)
      throws DescriptorParseException {
    double share = -1.0;
    if (partsNoOpt.length == 2 && partsNoOpt[1].length() >= 2
        && partsNoOpt[1].endsWith("%")) {
      String shareString = partsNoOpt[1];
      shareString = shareString.substring(0, shareString.length() - 1);
      try {
        share = Double.parseDouble(shareString);
      } catch (NumberFormatException e) {
        /* Handle below. */
      }
    }
    if (share < 0.0) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    return share;
  }

  private void parseDirreqV2RespLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV2Resp =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 0);
  }

  private void parseDirreqV3RespLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV3Resp =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 0);
  }

  private void parseDirreqV2DirectDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV2DirectDl =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 0);
  }

  private void parseDirreqV3DirectDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV3DirectDl =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 0);
  }

  private void parseDirreqV2TunneledDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV2TunneledDl =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 0);
  }

  private void parseDirreqV3TunneledDlLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.dirreqV3TunneledDl =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(
        line,partsNoOpt, 1, 0);
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
    long[] parsedStatsEndData = this.parseStatsEndLine(line, partsNoOpt,
        5);
    this.entryStatsEndMillis = parsedStatsEndData[0];
    this.entryStatsIntervalLength = parsedStatsEndData[1];
  }

  private void parseEntryIpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.entryIps = ParseHelper.parseCommaSeparatedKeyIntegerValueList(
        line, partsNoOpt, 1, 2);
  }

  private void parseCellStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    long[] parsedStatsEndData = this.parseStatsEndLine(line, partsNoOpt,
        5);
    this.cellStatsEndMillis = parsedStatsEndData[0];
    this.cellStatsIntervalLength = parsedStatsEndData[1];
  }

  private void parseCellProcessedCellsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.cellProcessedCells = ParseHelper
        .parseCommaSeparatedIntegerValueList(line, partsNoOpt, 1);
    if (this.cellProcessedCells.length != 10) {
      throw new DescriptorParseException("There must be exact ten values "
          + "in line '" + line + "'.");
    }
  }

  private void parseCellQueuedCellsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.cellQueuedCells = ParseHelper.parseCommaSeparatedDoubleValueList(
        line, partsNoOpt, 1);
    if (this.cellQueuedCells.length != 10) {
      throw new DescriptorParseException("There must be exact ten values "
          + "in line '" + line + "'.");
    }
  }

  private void parseCellTimeInQueueLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.cellTimeInQueue = ParseHelper
        .parseCommaSeparatedIntegerValueList(line, partsNoOpt, 1);
    if (this.cellTimeInQueue.length != 10) {
      throw new DescriptorParseException("There must be exact ten values "
          + "in line '" + line + "'.");
    }
  }

  private void parseCellCircuitsPerDecileLine(String line,
      String lineNoOpt, String[] partsNoOpt)
      throws DescriptorParseException {
    int circuits = -1;
    if (partsNoOpt.length == 2) {
      try {
        circuits = Integer.parseInt(partsNoOpt[1]);
      } catch (NumberFormatException e) {
        /* Handle below. */
      }
    }
    if (circuits < 0) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.cellCircuitsPerDecile = circuits;
  }

  private void parseConnBiDirectLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    long[] parsedStatsEndData = this.parseStatsEndLine(line, partsNoOpt,
        6);
    this.connBiDirectStatsEndMillis = parsedStatsEndData[0];
    this.connBiDirectStatsIntervalLength = parsedStatsEndData[1];
    Integer[] parsedConnBiDirectStats = ParseHelper
        .parseCommaSeparatedIntegerValueList(line, partsNoOpt, 5);
    if (parsedConnBiDirectStats.length != 4) {
      throw new DescriptorParseException("Illegal line '" + line + "' in "
          + "extra-info descriptor.");
    }
    this.connBiDirectBelow = parsedConnBiDirectStats[0];
    this.connBiDirectRead = parsedConnBiDirectStats[1];
    this.connBiDirectWrite = parsedConnBiDirectStats[2];
    this.connBiDirectBoth = parsedConnBiDirectStats[3];
  }

  private void parseExitStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    long[] parsedStatsEndData = this.parseStatsEndLine(line, partsNoOpt,
        5);
    this.exitStatsEndMillis = parsedStatsEndData[0];
    this.exitStatsIntervalLength = parsedStatsEndData[1];
  }

  private void parseExitKibibytesWrittenLine(String line,
      String lineNoOpt, String[] partsNoOpt)
      throws DescriptorParseException {
    this.exitKibibytesWritten = this.sortByPorts(ParseHelper
        .parseCommaSeparatedKeyLongValueList(line, partsNoOpt, 1, 0));
    this.verifyPorts(line, this.exitKibibytesWritten.keySet());
    this.verifyBytesOrStreams(line, this.exitKibibytesWritten.values());
  }

  private void parseExitKibibytesReadLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.exitKibibytesRead = this.sortByPorts(ParseHelper
        .parseCommaSeparatedKeyLongValueList(line, partsNoOpt, 1, 0));
    this.verifyPorts(line, this.exitKibibytesRead.keySet());
    this.verifyBytesOrStreams(line, this.exitKibibytesRead.values());
  }

  private void parseExitStreamsOpenedLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.exitStreamsOpened = this.sortByPorts(ParseHelper
        .parseCommaSeparatedKeyLongValueList(line, partsNoOpt, 1, 0));
    this.verifyPorts(line, this.exitStreamsOpened.keySet());
    this.verifyBytesOrStreams(line, this.exitStreamsOpened.values());
  }

  private SortedMap<String, Long> sortByPorts(
      SortedMap<String, Long> naturalOrder) {
    SortedMap<String, Long> byPortNumber =
        new TreeMap<String, Long>(new Comparator<String>() {
          public int compare(String arg0, String arg1) {
            int port0 = 0;
            int port1 = 0;
            try {
              port1 = Integer.parseInt(arg1);
            } catch (NumberFormatException e) {
              return -1;
            }
            try {
              port0 = Integer.parseInt(arg0);
            } catch (NumberFormatException e) {
              return 1;
            }
            if (port0 < port1) {
              return -1;
            } else if (port0 > port1) {
              return 1;
            } else {
              return 0;
            }
          }
        }
        );
    byPortNumber.putAll(naturalOrder);
    return byPortNumber;
  }

  private void verifyPorts(String line, Set<String> ports)
      throws DescriptorParseException {
    boolean valid = true;
    try {
      for (String port : ports) {
        if (!port.equals("other") && Integer.parseInt(port) <= 0) {
          valid = false;
          break;
        }
      }
    } catch (NumberFormatException e) {
      valid = false;
    }
    if (!valid) {
      throw new DescriptorParseException("Invalid port in line '" + line
          + "'.");
    }
  }

  private void verifyBytesOrStreams(String line,
      Collection<Long> bytesOrStreams) throws DescriptorParseException {
    boolean valid = true;
    for (long s : bytesOrStreams) {
      if (s < 0L) {
        valid = false;
        break;
      }
    }
    if (!valid) {
      throw new DescriptorParseException("Invalid value in line '" + line
          + "'.");
    }
  }

  private void parseBridgeStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    long[] parsedStatsEndData = this.parseStatsEndLine(line, partsNoOpt,
        5);
    this.bridgeStatsEndMillis = parsedStatsEndData[0];
    this.bridgeStatsIntervalLength = parsedStatsEndData[1];
  }

  private void parseBridgeStatsIpsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.bridgeIps =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 2);
  }

  private void parseBridgeIpVersionsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.bridgeIpVersions =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 2);
  }

  private void parseBridgeIpTransportsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.bridgeIpTransports =
        ParseHelper.parseCommaSeparatedKeyIntegerValueList(line,
        partsNoOpt, 1, 0);
  }

  private void parseTransportLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.transports.add(partsNoOpt[1]);
  }

  private void parseHidservStatsEndLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    long[] parsedStatsEndData = this.parseStatsEndLine(line, partsNoOpt,
        5);
    this.hidservStatsEndMillis = parsedStatsEndData[0];
    this.hidservStatsIntervalLength = parsedStatsEndData[1];
  }

  private void parseHidservRendRelayedCellsLine(String line,
      String lineNoOpt, String[] partsNoOpt)
      throws DescriptorParseException {
    if (partsNoOpt.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    try {
      this.hidservRendRelayedCells = Double.parseDouble(partsNoOpt[1]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.hidservRendRelayedCellsParameters =
        ParseHelper.parseSpaceSeparatedStringKeyDoubleValueMap(line,
        partsNoOpt, 2);
  }

  private void parseHidservDirOnionsSeenLine(String line,
      String lineNoOpt, String[] partsNoOpt)
      throws DescriptorParseException {
    if (partsNoOpt.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    try {
      this.hidservDirOnionsSeen = Double.parseDouble(partsNoOpt[1]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.hidservDirOnionsSeenParameters =
        ParseHelper.parseSpaceSeparatedStringKeyDoubleValueMap(line,
        partsNoOpt, 2);
  }

  private void parseRouterSignatureLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("router-signature")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseRouterDigestLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.extraInfoDigest = ParseHelper.parseTwentyByteHexString(line,
        partsNoOpt[1]);
  }

  private void parseIdentityEd25519Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 1) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseIdentityEd25519CryptoBlock(String cryptoString)
      throws DescriptorParseException {
    String masterKeyEd25519FromIdentityEd25519 =
        ParseHelper.parseMasterKeyEd25519FromIdentityEd25519CryptoBlock(
        cryptoString);
    if (this.masterKeyEd25519 != null && !this.masterKeyEd25519.equals(
        masterKeyEd25519FromIdentityEd25519)) {
      throw new DescriptorParseException("Mismatch between "
          + "identity-ed25519 and master-key-ed25519.");
    }
    this.masterKeyEd25519 = masterKeyEd25519FromIdentityEd25519;
  }

  private void parseMasterKeyEd25519Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    String masterKeyEd25519FromMasterKeyEd25519Line = partsNoOpt[1];
    if (this.masterKeyEd25519 != null && !masterKeyEd25519.equals(
        masterKeyEd25519FromMasterKeyEd25519Line)) {
      throw new DescriptorParseException("Mismatch between "
          + "identity-ed25519 and master-key-ed25519.");
    }
    this.masterKeyEd25519 = masterKeyEd25519FromMasterKeyEd25519Line;
  }

  private void parseRouterSigEd25519Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.routerSignatureEd25519 = partsNoOpt[1];
  }

  private void parseRouterDigestSha256Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    ParseHelper.parseThirtyTwoByteBase64String(line, partsNoOpt[1]);
    this.extraInfoDigestSha256 = partsNoOpt[1];
  }

  private void calculateDigest() throws DescriptorParseException {
    if (this.extraInfoDigest != null) {
      /* We already learned the descriptor digest of this bridge
       * descriptor from a "router-digest" line. */
      return;
    }
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "extra-info ";
      String sigToken = "\nrouter-signature\n";
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, sig - start);
        this.extraInfoDigest = DatatypeConverter.printHexBinary(
            MessageDigest.getInstance("SHA-1").digest(forDigest))
            .toLowerCase();
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    } catch (NoSuchAlgorithmException e) {
      /* Handle below. */
    }
    if (this.extraInfoDigest == null) {
      throw new DescriptorParseException("Could not calculate extra-info "
          + "descriptor digest.");
    }
  }

  private void calculateDigestSha256() throws DescriptorParseException {
    if (this.extraInfoDigestSha256 != null) {
      /* We already learned the descriptor digest of this bridge
       * descriptor from a "router-digest-sha256" line. */
      return;
    }
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "extra-info ";
      String sigToken = "\n-----END SIGNATURE-----\n";
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start, forDigest,
            0, sig - start);
        this.extraInfoDigestSha256 = DatatypeConverter.printBase64Binary(
            MessageDigest.getInstance("SHA-256").digest(forDigest))
            .replaceAll("=", "");
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    } catch (NoSuchAlgorithmException e) {
      /* Handle below. */
    }
    if (this.extraInfoDigestSha256 == null) {
      throw new DescriptorParseException("Could not calculate extra-info "
          + "descriptor SHA-256 digest.");
    }
  }

  private String extraInfoDigest;

  @Override
  public String getExtraInfoDigest() {
    return this.extraInfoDigest;
  }

  private String extraInfoDigestSha256;

  @Override
  public String getExtraInfoDigestSha256() {
    return this.extraInfoDigestSha256;
  }

  private String nickname;

  @Override
  public String getNickname() {
    return this.nickname;
  }

  private String fingerprint;

  @Override
  public String getFingerprint() {
    return this.fingerprint;
  }

  private long publishedMillis;

  @Override
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private BandwidthHistory readHistory;

  @Override
  public BandwidthHistory getReadHistory() {
    return this.readHistory;
  }

  private BandwidthHistory writeHistory;

  @Override
  public BandwidthHistory getWriteHistory() {
    return this.writeHistory;
  }

  private String geoipDbDigest;

  @Override
  public String getGeoipDbDigest() {
    return this.geoipDbDigest;
  }

  private String geoip6DbDigest;

  @Override
  public String getGeoip6DbDigest() {
    return this.geoip6DbDigest;
  }

  private long dirreqStatsEndMillis = -1L;

  @Override
  public long getDirreqStatsEndMillis() {
    return this.dirreqStatsEndMillis;
  }

  private long dirreqStatsIntervalLength = -1L;

  @Override
  public long getDirreqStatsIntervalLength() {
    return this.dirreqStatsIntervalLength;
  }

  private String dirreqV2Ips;

  @Override
  public SortedMap<String, Integer> getDirreqV2Ips() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV2Ips);
  }

  private String dirreqV3Ips;

  @Override
  public SortedMap<String, Integer> getDirreqV3Ips() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV3Ips);
  }

  private String dirreqV2Reqs;

  @Override
  public SortedMap<String, Integer> getDirreqV2Reqs() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV2Reqs);
  }

  private String dirreqV3Reqs;

  @Override
  public SortedMap<String, Integer> getDirreqV3Reqs() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV3Reqs);
  }

  private double dirreqV2Share = -1.0;

  @Override
  public double getDirreqV2Share() {
    return this.dirreqV2Share;
  }

  private double dirreqV3Share = -1.0;

  @Override
  public double getDirreqV3Share() {
    return this.dirreqV3Share;
  }

  private String dirreqV2Resp;

  @Override
  public SortedMap<String, Integer> getDirreqV2Resp() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV2Resp);
  }

  private String dirreqV3Resp;

  @Override
  public SortedMap<String, Integer> getDirreqV3Resp() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV3Resp);
  }

  private String dirreqV2DirectDl;

  @Override
  public SortedMap<String, Integer> getDirreqV2DirectDl() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV2DirectDl);
  }

  private String dirreqV3DirectDl;

  @Override
  public SortedMap<String, Integer> getDirreqV3DirectDl() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV3DirectDl);
  }

  private String dirreqV2TunneledDl;

  @Override
  public SortedMap<String, Integer> getDirreqV2TunneledDl() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV2TunneledDl);
  }

  private String dirreqV3TunneledDl;

  @Override
  public SortedMap<String, Integer> getDirreqV3TunneledDl() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.dirreqV3TunneledDl);
  }

  private BandwidthHistory dirreqReadHistory;

  @Override
  public BandwidthHistory getDirreqReadHistory() {
    return this.dirreqReadHistory;
  }

  private BandwidthHistory dirreqWriteHistory;

  @Override
  public BandwidthHistory getDirreqWriteHistory() {
    return this.dirreqWriteHistory;
  }

  private long entryStatsEndMillis = -1L;

  @Override
  public long getEntryStatsEndMillis() {
    return this.entryStatsEndMillis;
  }

  private long entryStatsIntervalLength = -1L;

  @Override
  public long getEntryStatsIntervalLength() {
    return this.entryStatsIntervalLength;
  }

  private String entryIps;

  @Override
  public SortedMap<String, Integer> getEntryIps() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.entryIps);
  }

  private long cellStatsEndMillis = -1L;

  @Override
  public long getCellStatsEndMillis() {
    return this.cellStatsEndMillis;
  }

  private long cellStatsIntervalLength = -1L;

  @Override
  public long getCellStatsIntervalLength() {
    return this.cellStatsIntervalLength;
  }

  private Integer[] cellProcessedCells;

  @Override
  public List<Integer> getCellProcessedCells() {
    return this.cellProcessedCells == null ? null
        : Arrays.asList(this.cellProcessedCells);
  }

  private Double[] cellQueuedCells;

  @Override
  public List<Double> getCellQueuedCells() {
    return this.cellQueuedCells == null ? null
        : Arrays.asList(this.cellQueuedCells);
  }

  private Integer[] cellTimeInQueue;

  @Override
  public List<Integer> getCellTimeInQueue() {
    return this.cellTimeInQueue == null ? null
        : Arrays.asList(this.cellTimeInQueue);
  }

  private int cellCircuitsPerDecile = -1;

  @Override
  public int getCellCircuitsPerDecile() {
    return this.cellCircuitsPerDecile;
  }

  private long connBiDirectStatsEndMillis = -1L;

  @Override
  public long getConnBiDirectStatsEndMillis() {
    return this.connBiDirectStatsEndMillis;
  }

  private long connBiDirectStatsIntervalLength = -1L;

  @Override
  public long getConnBiDirectStatsIntervalLength() {
    return this.connBiDirectStatsIntervalLength;
  }

  private int connBiDirectBelow = -1;

  @Override
  public int getConnBiDirectBelow() {
    return this.connBiDirectBelow;
  }

  private int connBiDirectRead = -1;

  @Override
  public int getConnBiDirectRead() {
    return this.connBiDirectRead;
  }

  private int connBiDirectWrite = -1;

  @Override
  public int getConnBiDirectWrite() {
    return this.connBiDirectWrite;
  }

  private int connBiDirectBoth = -1;

  @Override
  public int getConnBiDirectBoth() {
    return this.connBiDirectBoth;
  }

  private long exitStatsEndMillis = -1L;

  @Override
  public long getExitStatsEndMillis() {
    return this.exitStatsEndMillis;
  }

  private long exitStatsIntervalLength = -1L;

  @Override
  public long getExitStatsIntervalLength() {
    return this.exitStatsIntervalLength;
  }

  private SortedMap<String, Long> exitKibibytesWritten;

  @Override
  public SortedMap<String, Long> getExitKibibytesWritten() {
    return this.exitKibibytesWritten == null ? null
        : new TreeMap<>(this.exitKibibytesWritten);
  }

  private SortedMap<String, Long> exitKibibytesRead;

  @Override
  public SortedMap<String, Long> getExitKibibytesRead() {
    return this.exitKibibytesRead == null ? null
        : new TreeMap<>(this.exitKibibytesRead);
  }

  private SortedMap<String, Long> exitStreamsOpened;

  @Override
  public SortedMap<String, Long> getExitStreamsOpened() {
    return this.exitStreamsOpened == null ? null
        : new TreeMap<>(this.exitStreamsOpened);
  }

  private long geoipStartTimeMillis = -1L;

  @Override
  public long getGeoipStartTimeMillis() {
    return this.geoipStartTimeMillis;
  }

  private String geoipClientOrigins;

  @Override
  public SortedMap<String, Integer> getGeoipClientOrigins() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.geoipClientOrigins);
  }

  private long bridgeStatsEndMillis = -1L;

  @Override
  public long getBridgeStatsEndMillis() {
    return this.bridgeStatsEndMillis;
  }

  private long bridgeStatsIntervalLength = -1L;

  @Override
  public long getBridgeStatsIntervalLength() {
    return this.bridgeStatsIntervalLength;
  }

  private String bridgeIps;

  @Override
  public SortedMap<String, Integer> getBridgeIps() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.bridgeIps);
  }

  private String bridgeIpVersions;

  @Override
  public SortedMap<String, Integer> getBridgeIpVersions() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.bridgeIpVersions);
  }

  private String bridgeIpTransports;

  @Override
  public SortedMap<String, Integer> getBridgeIpTransports() {
    return ParseHelper.convertCommaSeparatedKeyIntegerValueList(
        this.bridgeIpTransports);
  }

  private List<String> transports = new ArrayList<>();

  @Override
  public List<String> getTransports() {
    return new ArrayList<>(this.transports);
  }

  private long hidservStatsEndMillis = -1L;

  @Override
  public long getHidservStatsEndMillis() {
    return this.hidservStatsEndMillis;
  }

  private long hidservStatsIntervalLength = -1L;

  @Override
  public long getHidservStatsIntervalLength() {
    return this.hidservStatsIntervalLength;
  }

  private Double hidservRendRelayedCells;

  @Override
  public Double getHidservRendRelayedCells() {
    return this.hidservRendRelayedCells;
  }

  private Map<String, Double> hidservRendRelayedCellsParameters;

  @Override
  public Map<String, Double> getHidservRendRelayedCellsParameters() {
    return this.hidservRendRelayedCellsParameters == null ? null
        : new HashMap<>(this.hidservRendRelayedCellsParameters);
  }

  private Double hidservDirOnionsSeen;

  @Override
  public Double getHidservDirOnionsSeen() {
    return this.hidservDirOnionsSeen;
  }

  private Map<String, Double> hidservDirOnionsSeenParameters;

  @Override
  public Map<String, Double> getHidservDirOnionsSeenParameters() {
    return this.hidservDirOnionsSeenParameters == null ? null
        : new HashMap<>(this.hidservDirOnionsSeenParameters);
  }

  private String routerSignature;

  @Override
  public String getRouterSignature() {
    return this.routerSignature;
  }

  private String identityEd25519;

  @Override
  public String getIdentityEd25519() {
    return this.identityEd25519;
  }

  private String masterKeyEd25519;

  @Override
  public String getMasterKeyEd25519() {
    return this.masterKeyEd25519;
  }

  private String routerSignatureEd25519;

  @Override
  public String getRouterSignatureEd25519() {
    return this.routerSignatureEd25519;
  }
}

