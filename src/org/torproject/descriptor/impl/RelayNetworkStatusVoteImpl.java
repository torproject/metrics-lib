/* Copyright 2011 The Tor Project
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
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;
import org.torproject.descriptor.RelayNetworkStatusVote;

/* TODO Find out if all keywords in the dir-source section are required.
 * They are not all mentioned in dir-spec.txt. */

/* Contains a network status vote. */
public class RelayNetworkStatusVoteImpl extends NetworkStatusImpl
    implements RelayNetworkStatusVote {

  protected static List<RelayNetworkStatusVote> parseVotes(
      byte[] votesBytes) {
    List<RelayNetworkStatusVote> parsedVotes =
        new ArrayList<RelayNetworkStatusVote>();
    List<byte[]> splitVotesBytes =
        NetworkStatusImpl.splitRawDescriptorBytes(votesBytes,
        "network-status-version 3");
    try {
      for (byte[] voteBytes : splitVotesBytes) {
        RelayNetworkStatusVote parsedVote =
            new RelayNetworkStatusVoteImpl(voteBytes);
        parsedVotes.add(parsedVote);
      }
    } catch (DescriptorParseException e) {
      /* TODO Handle this error somehow. */
      System.err.println("Failed to parse vote.  Skipping.");
      e.printStackTrace();
    }
    return parsedVotes;
  }

  protected RelayNetworkStatusVoteImpl(byte[] voteBytes)
      throws DescriptorParseException {
    super(voteBytes);
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList((
        "vote-status,consensus-methods,published,valid-after,fresh-until,"
        + "valid-until,voting-delay,known-flags,dir-source,"
        + "dir-key-certificate-version,fingerprint,dir-key-published,"
        + "dir-key-expires,directory-footer").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList((
        "client-versions,server-versions,params,contact,legacy-key").
        split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkFirstKeyword("network-status-version");
  }

  protected void parseHeader(byte[] headerBytes)
      throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(headerBytes)));
      String line;
      while ((line = br.readLine()) != null) {
        String[] parts = line.split(" ");
        String keyword = parts[0];
        if (keyword.equals("network-status-version")) {
          this.parseNetworkStatusVersionLine(line, parts);
        } else if (keyword.equals("vote-status")) {
          this.parseVoteStatusLine(line, parts);
        } else if (keyword.equals("consensus-methods")) {
          this.parseConsensusMethodsLine(line, parts);
        } else if (keyword.equals("published")) {
          this.parsePublishedLine(line, parts);
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
        } else {
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

  private void parseNetworkStatusVersionLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("network-status-version 3")) {
      throw new DescriptorParseException("Illegal network status version "
          + "number in line '" + line + "'.");
    }
    this.networkStatusVersion = 3;
  }

  private void parseVoteStatusLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2 || !parts[1].equals("vote")) {
      throw new DescriptorParseException("Line '" + line + "' indicates "
          + "that this is not a vote.");
    }
  }

  private void parseConsensusMethodsLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    this.consensusMethods = new ArrayList<Integer>();
    for (int i = 1; i < parts.length; i++) {
      int consensusMethod = -1;
      try {
        consensusMethod = Integer.parseInt(parts[i]);
      } catch (NumberFormatException e) {
        /* We'll notice below that consensusMethod is still -1. */
      }
      if (consensusMethod < 1) {
        throw new DescriptorParseException("Illegal consensus method "
            + "number in line '" + line + "'.");
      }
      this.consensusMethods.add(Integer.parseInt(parts[i]));
    }
  }

  private void parsePublishedLine(String line, String[] parts)
      throws DescriptorParseException {
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
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
    this.consensusParams = ParseHelper.parseKeyValuePairs(line, parts, 1);
  }

  protected void parseDirSource(byte[] dirSourceBytes)
      throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(dirSourceBytes)));
      String line;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {
        String[] parts = line.split(" ");
        String keyword = parts[0];
        if (keyword.equals("dir-source")) {
          this.parseDirSourceLine(line, parts);
        } else if (keyword.equals("contact")) {
          this.parseContactLine(line, parts);
        } else if (keyword.equals("dir-key-certificate-version")) {
          this.parseDirKeyCertificateVersionLine(line, parts);
        } else if (keyword.equals("fingerprint")) {
          /* Nothing new to learn here.  We already know the fingerprint
           * from the dir-source line. */
        } else if (keyword.equals("legacy-key")) {
          this.parseLegacyKeyLine(line, parts);
        } else if (keyword.equals("dir-key-published")) {
          this.parseDirKeyPublished(line, parts);
        } else if (keyword.equals("dir-key-expires")) {
          this.parseDirKeyExpiresLine(line, parts);
        } else if (keyword.equals("dir-identity-key") ||
            keyword.equals("dir-signing-key") ||
            keyword.equals("dir-key-crosscert") ||
            keyword.equals("dir-key-certification")) {
        } else if (line.startsWith("-----BEGIN")) {
          skipCrypto = true;
        } else if (line.startsWith("-----END")) {
          skipCrypto = false;
        } else if (!skipCrypto) {
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

  private void parseDirSourceLine(String line, String[] parts)
      throws DescriptorParseException {
    this.nickname = ParseHelper.parseNickname(line, parts[1]);
    this.identity = ParseHelper.parseTwentyByteHexString(line, parts[2]);
    this.address = ParseHelper.parseIpv4Address(line, parts[4]);
    this.dirPort = ParseHelper.parsePort(line, parts[5]);
    this.orPort = ParseHelper.parsePort(line, parts[6]);
  }

  private void parseContactLine(String line, String[] parts)
      throws DescriptorParseException {
    if (line.length() > "contact ".length()) {
      this.contactLine = line.substring("contact ".length());
    } else {
      this.contactLine = "";
    }
  }

  private void parseDirKeyCertificateVersionLine(String line,
      String[] parts) throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    try {
      this.dirKeyCertificateVersion = Integer.parseInt(parts[1]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal dir key certificate "
          + "version in line '" + line + "'.");
    }
    if (this.dirKeyCertificateVersion < 1) {
      throw new DescriptorParseException("Illegal dir key certificate "
          + "version in line '" + line + "'.");
    }
  }

  private void parseLegacyKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.legacyKey = ParseHelper.parseTwentyByteHexString(line, parts[2]);
  }

  private void parseDirKeyPublished(String line, String[] parts)
      throws DescriptorParseException {
    this.dirKeyPublishedMillis = ParseHelper.parseTimestampAtIndex(line,
        parts, 1, 2);
  }

  private void parseDirKeyExpiresLine(String line, String[] parts)
      throws DescriptorParseException {
    this.dirKeyExpiresMillis = ParseHelper.parseTimestampAtIndex(line,
        parts, 1, 2);
  }

  protected void parseFooter(byte[] footerBytes) {
    /* There is nothing in the footer that we'd want to parse. */
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String identity;
  public String getIdentity() {
    return this.identity;
  }

  private String address;
  public String getAddress() {
    return this.address;
  }

  private int dirPort;
  public int getDirport() {
    return this.dirPort;
  }

  private int orPort;
  public int getOrport() {
    return this.orPort;
  }

  private String contactLine;
  public String getContactLine() {
    return this.contactLine;
  }

  private int dirKeyCertificateVersion;
  public int getDirKeyCertificateVersion() {
    return this.dirKeyCertificateVersion;
  }

  private String legacyKey;
  public String getLegacyKey() {
    return this.legacyKey;
  }

  private long dirKeyPublishedMillis;
  public long getDirKeyPublishedMillis() {
    return this.dirKeyPublishedMillis;
  }

  private long dirKeyExpiresMillis;
  public long getDirKeyExpiresMillis() {
    return this.dirKeyExpiresMillis;
  }

  private String signingKeyDigest;
  public String getSigningKeyDigest() {
    return this.signingKeyDigest;
  }

  private int networkStatusVersion;
  public int getNetworkStatusVersion() {
    return this.networkStatusVersion;
  }

  private List<Integer> consensusMethods;
  public List<Integer> getConsensusMethods() {
    return new ArrayList<Integer>(this.consensusMethods);
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
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
}

