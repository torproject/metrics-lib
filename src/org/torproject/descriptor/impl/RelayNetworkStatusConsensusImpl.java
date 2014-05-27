/* Copyright 2011--2014 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

import org.apache.commons.codec.digest.DigestUtils;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

/* Contains a network status consensus or microdesc consensus. */
public class RelayNetworkStatusConsensusImpl extends NetworkStatusImpl
    implements RelayNetworkStatusConsensus {

  protected static List<RelayNetworkStatusConsensus> parseConsensuses(
      byte[] consensusesBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<RelayNetworkStatusConsensus> parsedConsensuses =
        new ArrayList<RelayNetworkStatusConsensus>();
    List<byte[]> splitConsensusBytes =
        DescriptorImpl.splitRawDescriptorBytes(consensusesBytes,
        "network-status-version 3");
    for (byte[] consensusBytes : splitConsensusBytes) {
      RelayNetworkStatusConsensus parsedConsensus =
          new RelayNetworkStatusConsensusImpl(consensusBytes,
              failUnrecognizedDescriptorLines);
      parsedConsensuses.add(parsedConsensus);
    }
    return parsedConsensuses;
  }

  protected RelayNetworkStatusConsensusImpl(byte[] consensusBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(consensusBytes, failUnrecognizedDescriptorLines, true, false);
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList((
        "vote-status,consensus-method,valid-after,fresh-until,"
        + "valid-until,voting-delay,known-flags").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList((
        "client-versions,server-versions,params,directory-footer,"
        + "bandwidth-weights").split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkFirstKeyword("network-status-version");
    this.clearParsedKeywords();
    this.calculateDigest();
  }

  private void calculateDigest() throws DescriptorParseException {
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "network-status-version ";
      String sigToken = "\ndirectory-signature ";
      if (!ascii.contains(sigToken)) {
        return;
      }
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, sig - start);
        this.consensusDigest = DigestUtils.shaHex(forDigest);
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    }
    if (this.consensusDigest == null) {
      throw new DescriptorParseException("Could not calculate consensus "
          + "digest.");
    }
  }

  protected void parseHeader(byte[] headerBytes)
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(headerBytes)).useDelimiter("\n");
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ");
      String keyword = parts[0];
      if (keyword.equals("network-status-version")) {
        this.parseNetworkStatusVersionLine(line, parts);
      } else if (keyword.equals("vote-status")) {
        this.parseVoteStatusLine(line, parts);
      } else if (keyword.equals("consensus-method")) {
        this.parseConsensusMethodLine(line, parts);
      } else if (keyword.equals("valid-after")) {
        this.parseValidAfterLine(line, parts);
      } else if (keyword.equals("fresh-until")) {
        this.parseFreshUntilLine(line, parts);
      } else if (keyword.equals("valid-until")) {
        this.parseValidUntilLine(line, parts);
      } else if (keyword.equals("voting-delay")) {
        this.parseVotingDelayLine(line, parts);
      } else if (keyword.equals("client-versions")) {
        this.parseClientVersionsLine(line, parts);
      } else if (keyword.equals("server-versions")) {
        this.parseServerVersionsLine(line, parts);
      } else if (keyword.equals("known-flags")) {
        this.parseKnownFlagsLine(line, parts);
      } else if (keyword.equals("params")) {
        this.parseParamsLine(line, parts);
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in consensus.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<String>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  private boolean microdescConsensus = false;
  protected void parseStatusEntry(byte[] statusEntryBytes)
      throws DescriptorParseException {
    NetworkStatusEntryImpl statusEntry = new NetworkStatusEntryImpl(
        statusEntryBytes, this.microdescConsensus,
        this.failUnrecognizedDescriptorLines);
    this.statusEntries.put(statusEntry.getFingerprint(), statusEntry);
    List<String> unrecognizedStatusEntryLines = statusEntry.
        getAndClearUnrecognizedLines();
    if (unrecognizedStatusEntryLines != null) {
      if (this.unrecognizedLines == null) {
        this.unrecognizedLines = new ArrayList<String>();
      }
      this.unrecognizedLines.addAll(unrecognizedStatusEntryLines);
    }
  }

  protected void parseFooter(byte[] footerBytes)
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(footerBytes)).useDelimiter("\n");
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ");
      String keyword = parts[0];
      if (keyword.equals("directory-footer")) {
      } else if (keyword.equals("bandwidth-weights")) {
        this.parseBandwidthWeightsLine(line, parts);
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in consensus.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<String>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  private void parseNetworkStatusVersionLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.startsWith("network-status-version 3")) {
      throw new DescriptorParseException("Illegal network status version "
          + "number in line '" + line + "'.");
    }
    this.networkStatusVersion = 3;
    if (parts.length == 3) {
      this.consensusFlavor = parts[2];
      if (this.consensusFlavor.equals("microdesc")) {
        this.microdescConsensus = true;
      }
    } else if (parts.length != 2) {
      throw new DescriptorParseException("Illegal network status version "
          + "line '" + line + "'.");
    }
  }

  private void parseVoteStatusLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2 || !parts[1].equals("consensus")) {
      throw new DescriptorParseException("Line '" + line + "' indicates "
          + "that this is not a consensus.");
    }
  }

  private void parseConsensusMethodLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in consensus.");
    }
    try {
      this.consensusMethod = Integer.parseInt(parts[1]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal consensus method "
          + "number in line '" + line + "'.");
    }
    if (this.consensusMethod < 1) {
      throw new DescriptorParseException("Illegal consensus method "
          + "number in line '" + line + "'.");
    }
  }

  private void parseValidAfterLine(String line, String[] parts)
      throws DescriptorParseException {
    this.validAfterMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseFreshUntilLine(String line, String[] parts)
      throws DescriptorParseException {
    this.freshUntilMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseValidUntilLine(String line, String[] parts)
      throws DescriptorParseException {
    this.validUntilMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseVotingDelayLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 3) {
      throw new DescriptorParseException("Wrong number of values in line "
          + "'" + line + "'.");
    }
    try {
      this.voteSeconds = Long.parseLong(parts[1]);
      this.distSeconds = Long.parseLong(parts[2]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal values in line '" + line
          + "'.");
    }
  }

  private void parseClientVersionsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.recommendedClientVersions = this.parseClientOrServerVersions(
        line, parts);
  }

  private void parseServerVersionsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.recommendedServerVersions = this.parseClientOrServerVersions(
        line, parts);
  }

  private List<String> parseClientOrServerVersions(String line,
      String[] parts) throws DescriptorParseException {
    List<String> result = new ArrayList<String>();
    if (parts.length == 1) {
      return result;
    } else if (parts.length > 2) {
      throw new DescriptorParseException("Illegal versions line '" + line
          + "'.");
    }
    String[] versions = parts[1].split(",", -1);
    for (int i = 0; i < versions.length; i++) {
      String version = versions[i];
      if (version.length() < 1) {
        throw new DescriptorParseException("Illegal versions line '"
            + line + "'.");
      }
      result.add(version);
    }
    return result;
  }

  private void parseKnownFlagsLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 2) {
      throw new DescriptorParseException("No known flags in line '" + line
          + "'.");
    }
    this.knownFlags = new TreeSet<String>();
    for (int i = 1; i < parts.length; i++) {
      this.knownFlags.add(parts[i]);
    }
  }

  private void parseParamsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.consensusParams = ParseHelper.parseKeyValueIntegerPairs(line,
        parts, 1, "=");
  }

  private void parseBandwidthWeightsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.bandwidthWeights = ParseHelper.parseKeyValueIntegerPairs(line,
        parts, 1, "=");
  }

  private String consensusDigest;
  public String getConsensusDigest() {
    return this.consensusDigest;
  }

  private int networkStatusVersion;
  public int getNetworkStatusVersion() {
    return this.networkStatusVersion;
  }

  private String consensusFlavor;
  public String getConsensusFlavor() {
    return this.consensusFlavor;
  }

  private int consensusMethod;
  public int getConsensusMethod() {
    return this.consensusMethod;
  }

  private long validAfterMillis;
  public long getValidAfterMillis() {
    return this.validAfterMillis;
  }

  private long freshUntilMillis;
  public long getFreshUntilMillis() {
    return this.freshUntilMillis;
  }

  private long validUntilMillis;
  public long getValidUntilMillis() {
    return this.validUntilMillis;
  }

  private long voteSeconds;
  public long getVoteSeconds() {
    return this.voteSeconds;
  }

  private long distSeconds;
  public long getDistSeconds() {
    return this.distSeconds;
  }

  private List<String> recommendedClientVersions;
  public List<String> getRecommendedClientVersions() {
    return this.recommendedClientVersions == null ? null :
        new ArrayList<String>(this.recommendedClientVersions);
  }

  private List<String> recommendedServerVersions;
  public List<String> getRecommendedServerVersions() {
    return this.recommendedServerVersions == null ? null :
        new ArrayList<String>(this.recommendedServerVersions);
  }

  private SortedSet<String> knownFlags;
  public SortedSet<String> getKnownFlags() {
    return new TreeSet<String>(this.knownFlags);
  }

  private SortedMap<String, Integer> consensusParams;
  public SortedMap<String, Integer> getConsensusParams() {
    return this.consensusParams == null ? null:
        new TreeMap<String, Integer>(this.consensusParams);
  }

  private SortedMap<String, Integer> bandwidthWeights;
  public SortedMap<String, Integer> getBandwidthWeights() {
    return this.bandwidthWeights == null ? null :
        new TreeMap<String, Integer>(this.bandwidthWeights);
  }
}

