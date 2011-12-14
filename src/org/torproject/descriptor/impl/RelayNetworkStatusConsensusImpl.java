/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DirSourceEntry;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

/* Contains a network status consensus. */
public class RelayNetworkStatusConsensusImpl
    implements RelayNetworkStatusConsensus {

  protected static List<RelayNetworkStatusConsensus> parseConsensuses(
      byte[] consensusBytes) {
    List<RelayNetworkStatusConsensus> parsedConsensuses =
        new ArrayList<RelayNetworkStatusConsensus>();
    String startToken = "network-status-version 3";
    String splitToken = "\n" + startToken;
    String ascii = new String(consensusBytes);
    int length = consensusBytes.length, start = ascii.indexOf(startToken);
    while (start < length) {
      int end = ascii.indexOf(splitToken, start);
      if (end < 0) {
        end = length;
      } else {
        end += 1;
      }
      byte[] descBytes = new byte[end - start];
      System.arraycopy(consensusBytes, start, descBytes, 0, end - start);
      start = end;
      try {
        RelayNetworkStatusConsensus parsedConsensus =
            new RelayNetworkStatusConsensusImpl(descBytes);
        parsedConsensuses.add(parsedConsensus);
      } catch (DescriptorParseException e) {
        /* TODO Handle this error somehow. */
        System.err.println("Failed to parse consensus.  Skipping.");
        e.printStackTrace();
      }
    }
    return parsedConsensuses;
  }

  protected RelayNetworkStatusConsensusImpl(byte[] consensusBytes)
      throws DescriptorParseException {
    this.consensusBytes = consensusBytes;
    this.initializeKeywords();
    this.parseConsensusBytes();
    this.checkKeywords();
  }

  private SortedSet<String> exactlyOnceKeywords, atMostOnceKeywords;
  private void initializeKeywords() {
    this.exactlyOnceKeywords = new TreeSet<String>();
    this.exactlyOnceKeywords.add("vote-status");
    this.exactlyOnceKeywords.add("consensus-method");
    this.exactlyOnceKeywords.add("valid-after");
    this.exactlyOnceKeywords.add("fresh-until");
    this.exactlyOnceKeywords.add("valid-until");
    this.exactlyOnceKeywords.add("voting-delay");
    this.exactlyOnceKeywords.add("known-flags");
    this.exactlyOnceKeywords.add("directory-footer");
    this.atMostOnceKeywords = new TreeSet<String>();
    this.atMostOnceKeywords.add("client-versions");
    this.atMostOnceKeywords.add("server-versions");
    this.atMostOnceKeywords.add("params");
    this.atMostOnceKeywords.add("bandwidth-weights");
  }

  private void parsedExactlyOnceKeyword(String keyword)
      throws DescriptorParseException {
    if (!this.exactlyOnceKeywords.contains(keyword)) {
      throw new DescriptorParseException("Duplicate '" + keyword
          + "' line in consensus.");
    }
    this.exactlyOnceKeywords.remove(keyword);
  }

  private void parsedAtMostOnceKeyword(String keyword)
      throws DescriptorParseException {
    if (!this.atMostOnceKeywords.contains(keyword)) {
      throw new DescriptorParseException("Duplicate " + keyword + "line "
          + "in consensus.");
    }
    this.atMostOnceKeywords.remove(keyword);
  }

  private void checkKeywords() throws DescriptorParseException {
    if (!this.exactlyOnceKeywords.isEmpty()) {
      throw new DescriptorParseException("Consensus does not contain a '"
          + this.exactlyOnceKeywords.first() + "' line.");
    }
  }

  private void parseConsensusBytes() throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.consensusBytes)));
      String line = br.readLine();
      if (line == null || !line.equals("network-status-version 3")) {
        throw new DescriptorParseException("Consensus must start with "
            + "line 'network-status-version 3'.");
      }
      this.networkStatusVersion = 3;
      StringBuilder dirSourceEntryLines = null, statusEntryLines = null;
      boolean skipSignature = false;
      while ((line = br.readLine()) != null) {
        if (line.length() < 1) {
          throw new DescriptorParseException("Empty lines are not "
              + "allowed in a consensus.");
        }
        String[] parts = line.split(" ");
        if (parts.length < 1) {
          throw new DescriptorParseException("No keyword found in line '"
              + line + "'.");
        }
        String keyword = parts[0];
        if (keyword.length() < 1) {
          throw new DescriptorParseException("Empty keyword in line '"
              + line + "'.");
        }
        if (keyword.equals("vote-status")) {
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
        } else if (keyword.equals("dir-source") || keyword.equals("r") ||
            keyword.equals("directory-footer")) {
          if (dirSourceEntryLines != null) {
            this.parseDirSourceEntryLines(dirSourceEntryLines.toString());
            dirSourceEntryLines = null;
          }
          if (statusEntryLines != null) {
            this.parseStatusEntryLines(statusEntryLines.toString());
            statusEntryLines = null;
          }
          if (keyword.equals("dir-source")) {
            dirSourceEntryLines = new StringBuilder(line + "\n");
          } else if (keyword.equals("r")) {
            statusEntryLines = new StringBuilder(line + "\n");
          } else if (keyword.equals("directory-footer")) {
            this.parsedExactlyOnceKeyword("directory-footer");
          }
        } else if (keyword.equals("contact") ||
            keyword.equals("vote-digest")) {
          if (dirSourceEntryLines == null) {
            throw new DescriptorParseException(keyword + " line with no "
                + "preceding dir-source line.");
          }
          dirSourceEntryLines.append(line + "\n");
        } else if (keyword.equals("s") || keyword.equals("v") ||
            keyword.equals("w") || keyword.equals("p")) {
          if (statusEntryLines == null) {
            throw new DescriptorParseException(keyword + " line with no "
                + "preceding r line.");
          }
          statusEntryLines.append(line + "\n");
        } else if (keyword.equals("bandwidth-weights")) {
          this.parseBandwidthWeightsLine(line, parts);
        } else if (keyword.equals("directory-signature")) {
          this.parseDirectorySignatureLine(line, parts);
        } else if (line.equals("-----BEGIN SIGNATURE-----")) {
          skipSignature = true;
        } else if (line.equals("-----END SIGNATURE-----")) {
          skipSignature = false;
        } else if (!skipSignature) {
          /* TODO Is throwing an exception the right thing to do here?
           * This is probably fine for development, but once the library
           * is in production use, this seems annoying. */
          throw new DescriptorParseException("Unrecognized line '" + line
              + "'.");
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  private void parseVoteStatusLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("vote-status");
    if (parts.length != 2 || !parts[1].equals("consensus")) {
      throw new DescriptorParseException("Line '" + line + "' indicates "
          + "that this is not a consensus.");
    }
  }

  private void parseConsensusMethodLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("consensus-method");
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
    this.parsedExactlyOnceKeyword("valid-after");
    this.validAfterMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseFreshUntilLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("fresh-until");
    this.freshUntilMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseValidUntilLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("valid-until");
    this.validUntilMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseVotingDelayLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("voting-delay");
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
    this.parsedAtMostOnceKeyword("client-versions");
    this.recommendedClientVersions = this.parseClientOrServerVersions(
        line, parts);
  }

  private void parseServerVersionsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("server-versions");
    this.recommendedServerVersions = this.parseClientOrServerVersions(
        line, parts);
  }

  private SortedSet<String> parseClientOrServerVersions(String line,
      String[] parts) throws DescriptorParseException {
    SortedSet<String> result = new TreeSet<String>();
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
    this.parsedExactlyOnceKeyword("known-flags");
    if (parts.length < 2) {
      throw new DescriptorParseException("No known flags in line '" + line
          + "'.");
    }
    for (int i = 1; i < parts.length; i++) {
      this.knownFlags.add(parts[i]);
    }
  }

  private void parseParamsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("params");
    this.consensusParams = ParseHelper.parseKeyValuePairs(line, parts, 1);
  }

  private void parseDirSourceEntryLines(String string)
      throws DescriptorParseException {
    DirSourceEntry dirSourceEntry = new DirSourceEntryImpl(
        string.getBytes());
    this.dirSourceEntries.put(dirSourceEntry.getIdentity(),
        dirSourceEntry);
  }

  private void parseStatusEntryLines(String string)
      throws DescriptorParseException {
    NetworkStatusEntryImpl statusEntry = new NetworkStatusEntryImpl(
        string.getBytes());
    this.statusEntries.put(statusEntry.getFingerprint(), statusEntry);
  }

  private void parseBandwidthWeightsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("bandwidth-weights");
    this.bandwidthWeights = ParseHelper.parseKeyValuePairs(line, parts,
        1);
  }

  private void parseDirectorySignatureLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 3) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    String identity = ParseHelper.parseTwentyByteHexString(line,
        parts[1]);
    String signingKeyDigest = ParseHelper.parseTwentyByteHexString(line,
        parts[2]);
    this.directorySignatures.put(identity, signingKeyDigest);
  }

  private byte[] consensusBytes;
  public byte[] getRawDescriptorBytes() {
    return this.consensusBytes;
  }

  private int networkStatusVersion;
  public int getNetworkStatusVersion() {
    return this.networkStatusVersion;
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

  private SortedSet<String> recommendedClientVersions;
  public SortedSet<String> getRecommendedClientVersions() {
    return this.recommendedClientVersions == null ? null :
        new TreeSet<String>(this.recommendedClientVersions);
  }

  private SortedSet<String> recommendedServerVersions;
  public SortedSet<String> getRecommendedServerVersions() {
    return this.recommendedServerVersions == null ? null :
        new TreeSet<String>(this.recommendedServerVersions);
  }

  private SortedSet<String> knownFlags = new TreeSet<String>();
  public SortedSet<String> getKnownFlags() {
    return new TreeSet<String>(this.knownFlags);
  }

  private SortedMap<String, Integer> consensusParams;
  public SortedMap<String, Integer> getConsensusParams() {
    return this.consensusParams == null ? null:
        new TreeMap<String, Integer>(this.consensusParams);
  }

  private SortedMap<String, DirSourceEntry> dirSourceEntries =
      new TreeMap<String, DirSourceEntry>();
  public SortedMap<String, DirSourceEntry> getDirSourceEntries() {
    return new TreeMap<String, DirSourceEntry>(this.dirSourceEntries);
  }

  private SortedMap<String, NetworkStatusEntry> statusEntries =
      new TreeMap<String, NetworkStatusEntry>();
  public SortedMap<String, NetworkStatusEntry> getStatusEntries() {
    return new TreeMap<String, NetworkStatusEntry>(this.statusEntries);
  }
  public boolean containsStatusEntry(String fingerprint) {
    return this.statusEntries.containsKey(fingerprint);
  }
  public NetworkStatusEntry getStatusEntry(String fingerprint) {
    return this.statusEntries.get(fingerprint);
  }

  private SortedMap<String, String> directorySignatures =
      new TreeMap<String, String>();
  public SortedMap<String, String> getDirectorySignatures() {
    return new TreeMap<String, String>(this.directorySignatures);
  }

  private SortedMap<String, Integer> bandwidthWeights;
  public SortedMap<String, Integer> getBandwidthWeights() {
    return this.bandwidthWeights == null ? null :
        new TreeMap<String, Integer>(this.bandwidthWeights);
  }
}

