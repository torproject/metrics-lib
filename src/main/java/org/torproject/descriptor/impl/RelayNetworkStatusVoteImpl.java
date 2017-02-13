/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DirectorySignature;
import org.torproject.descriptor.RelayNetworkStatusVote;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/* Contains a network status vote. */
public class RelayNetworkStatusVoteImpl extends NetworkStatusImpl
    implements RelayNetworkStatusVote {

  protected static List<RelayNetworkStatusVote> parseVotes(
      byte[] votesBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<RelayNetworkStatusVote> parsedVotes = new ArrayList<>();
    List<byte[]> splitVotesBytes =
        DescriptorImpl.splitRawDescriptorBytes(votesBytes,
        "network-status-version 3");
    for (byte[] voteBytes : splitVotesBytes) {
      RelayNetworkStatusVote parsedVote =
          new RelayNetworkStatusVoteImpl(voteBytes,
              failUnrecognizedDescriptorLines);
      parsedVotes.add(parsedVote);
    }
    return parsedVotes;
  }

  protected RelayNetworkStatusVoteImpl(byte[] voteBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(voteBytes, failUnrecognizedDescriptorLines, false, false);
    Set<String> exactlyOnceKeywords = new HashSet<>(Arrays.asList((
        "vote-status,published,valid-after,fresh-until,"
        + "valid-until,voting-delay,known-flags,dir-source,"
        + "dir-key-certificate-version,fingerprint,dir-key-published,"
        + "dir-key-expires,dir-identity-key,dir-signing-key,"
        + "dir-key-certification").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<>(Arrays.asList((
        "consensus-methods,client-versions,server-versions,"
        + "recommended-client-protocols,recommended-relay-protocols,"
        + "required-client-protocols,required-relay-protocols,"
        + "flag-thresholds,params,contact,shared-rand-participate,"
        + "shared-rand-previous-value,shared-rand-current-value,"
        + "legacy-key,dir-key-crosscert,dir-address,directory-footer")
        .split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    Set<String> atLeastOnceKeywords = new HashSet<>(Arrays.asList(
        "directory-signature"));
    this.checkAtLeastOnceKeywords(atLeastOnceKeywords);
    this.checkFirstKeyword("network-status-version");
    this.clearParsedKeywords();
  }

  protected void parseHeader(byte[] headerBytes)
      throws DescriptorParseException {
    /* Initialize flag-thresholds values here for the case that the vote
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

    Scanner scanner = new Scanner(new String(headerBytes)).useDelimiter("\n");
    String nextCrypto = "";
    StringBuilder crypto = null;
    while (scanner.hasNext()) {
      String line = scanner.next();
      String[] parts = line.split("[ \t]+");
      String keyword = parts[0];
      switch (keyword) {
        case "network-status-version":
          this.parseNetworkStatusVersionLine(line, parts);
          break;
        case "vote-status":
          this.parseVoteStatusLine(line, parts);
          break;
        case "consensus-methods":
          this.parseConsensusMethodsLine(line, parts);
          break;
        case "published":
          this.parsePublishedLine(line, parts);
          break;
        case "valid-after":
          this.parseValidAfterLine(line, parts);
          break;
        case "fresh-until":
          this.parseFreshUntilLine(line, parts);
          break;
        case "valid-until":
          this.parseValidUntilLine(line, parts);
          break;
        case "voting-delay":
          this.parseVotingDelayLine(line, parts);
          break;
        case "client-versions":
          this.parseClientVersionsLine(line, parts);
          break;
        case "server-versions":
          this.parseServerVersionsLine(line, parts);
          break;
        case "recommended-client-protocols":
          this.parseRecommendedClientProtocolsLine(line, parts);
          break;
        case "recommended-relay-protocols":
          this.parseRecommendedRelayProtocolsLine(line, parts);
          break;
        case "required-client-protocols":
          this.parseRequiredClientProtocolsLine(line, parts);
          break;
        case "required-relay-protocols":
          this.parseRequiredRelayProtocolsLine(line, parts);
          break;
        case "package":
          this.parsePackageLine(line, parts);
          break;
        case "known-flags":
          this.parseKnownFlagsLine(line, parts);
          break;
        case "flag-thresholds":
          this.parseFlagThresholdsLine(line, parts);
          break;
        case "params":
          this.parseParamsLine(line, parts);
          break;
        case "dir-source":
          this.parseDirSourceLine(line, parts);
          break;
        case "contact":
          this.parseContactLine(line, parts);
          break;
        case "shared-rand-participate":
          this.parseSharedRandParticipateLine(line, parts);
          break;
        case "shared-rand-commit":
          this.parseSharedRandCommitLine(line, parts);
          break;
        case "shared-rand-previous-value":
          this.parseSharedRandPreviousValueLine(line, parts);
          break;
        case "shared-rand-current-value":
          this.parseSharedRandCurrentValueLine(line, parts);
          break;
        case "dir-key-certificate-version":
          this.parseDirKeyCertificateVersionLine(line, parts);
          break;
        case "dir-address":
          this.parseDirAddressLine(line, parts);
          break;
        case "fingerprint":
          this.parseFingerprintLine(line, parts);
          break;
        case "legacy-dir-key":
          this.parseLegacyDirKeyLine(line, parts);
          break;
        case "dir-key-published":
          this.parseDirKeyPublished(line, parts);
          break;
        case "dir-key-expires":
          this.parseDirKeyExpiresLine(line, parts);
          break;
        case "dir-identity-key":
          this.parseDirIdentityKeyLine(line, parts);
          nextCrypto = "dir-identity-key";
          break;
        case "dir-signing-key":
          this.parseDirSigningKeyLine(line, parts);
          nextCrypto = "dir-signing-key";
          break;
        case "dir-key-crosscert":
          this.parseDirKeyCrosscertLine(line, parts);
          nextCrypto = "dir-key-crosscert";
          break;
        case "dir-key-certification":
          this.parseDirKeyCertificationLine(line, parts);
          nextCrypto = "dir-key-certification";
          break;
        case "-----BEGIN":
          crypto = new StringBuilder();
          crypto.append(line).append("\n");
          break;
        case "-----END":
          crypto.append(line).append("\n");
          String cryptoString = crypto.toString();
          crypto = null;
          switch (nextCrypto) {
            case "dir-identity-key":
              this.dirIdentityKey = cryptoString;
              break;
            case "dir-signing-key":
              this.dirSigningKey = cryptoString;
              break;
            case "dir-key-crosscert":
              this.dirKeyCrosscert = cryptoString;
              break;
            case "dir-key-certification":
              this.dirKeyCertification = cryptoString;
              break;
            default:
              throw new DescriptorParseException("Unrecognized crypto "
                  + "block in vote.");
          }
          nextCrypto = "";
          break;
        default:
          if (crypto != null) {
            crypto.append(line).append("\n");
          } else {
            if (this.failUnrecognizedDescriptorLines) {
              throw new DescriptorParseException("Unrecognized line '"
                  + line + "' in vote.");
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
    Integer[] consensusMethods = new Integer[parts.length - 1];
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
      consensusMethods[i - 1] = consensusMethod;
    }
    this.consensusMethods = consensusMethods;
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

  private void parseRecommendedClientProtocolsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.recommendedClientProtocols = ParseHelper.parseProtocolVersions(line,
        line, parts);
  }

  private void parseRecommendedRelayProtocolsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.recommendedRelayProtocols = ParseHelper.parseProtocolVersions(line,
        line, parts);
  }

  private void parseRequiredClientProtocolsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.requiredClientProtocols = ParseHelper.parseProtocolVersions(line,
        line, parts);
  }

  private void parseRequiredRelayProtocolsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.requiredRelayProtocols = ParseHelper.parseProtocolVersions(line, line,
        parts);
  }

  private void parsePackageLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 5) {
      throw new DescriptorParseException("Wrong number of values in line "
          + "'" + line + "'.");
    }
    if (this.packageLines == null) {
      this.packageLines = new ArrayList<>();
    }
    this.packageLines.add(line.substring("package ".length()));
  }

  private void parseKnownFlagsLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 2) {
      throw new DescriptorParseException("No known flags in line '" + line
          + "'.");
    }
    String[] knownFlags = new String[parts.length - 1];
    for (int i = 1; i < parts.length; i++) {
      knownFlags[i - 1] = parts[i];
    }
    this.knownFlags = knownFlags;
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
            this.guardWfu = Double.parseDouble(e.getValue()
                .replaceAll("%", ""));
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
          default:
            // empty
        }
      }
    } catch (NumberFormatException ex) {
      throw new DescriptorParseException("Illegal value in line '"
          + line + "'.");
    }
  }

  private void parseParamsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.consensusParams = ParseHelper.parseKeyValueIntegerPairs(line,
        parts, 1, "=");
  }

  private void parseDirSourceLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 7) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    this.nickname = ParseHelper.parseNickname(line, parts[1]);
    this.identity = ParseHelper.parseTwentyByteHexString(line, parts[2]);
    if (parts[3].length() < 1) {
      throw new DescriptorParseException("Illegal hostname in '" + line
          + "'.");
    }
    this.hostname = parts[3];
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

  private void parseSharedRandParticipateLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 1) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    this.sharedRandParticipate = true;
  }

  private void parseSharedRandCommitLine(String line, String[] parts)
      throws DescriptorParseException {
    if (this.sharedRandCommitLines == null) {
      this.sharedRandCommitLines = new ArrayList<>();
    }
    this.sharedRandCommitLines.add(line);
  }

  private void parseSharedRandPreviousValueLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 3) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    try {
      this.sharedRandPreviousNumReveals = Integer.parseInt(parts[1]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    this.sharedRandPreviousValue = parts[2];
  }

  private void parseSharedRandCurrentValueLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 3) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    try {
      this.sharedRandCurrentNumReveals = Integer.parseInt(parts[1]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    this.sharedRandCurrentValue = parts[2];
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

  private void parseDirAddressLine(String line, String[] parts) {
    /* Nothing new to learn here.  Also, this line hasn't been observed
     * "in the wild" yet.  Maybe it's just an urban legend. */
  }

  private void parseFingerprintLine(String line, String[] parts)
      throws DescriptorParseException {
    /* Nothing new to learn here.  We already know the fingerprint from
     * the dir-source line.  But we should at least check that there's a
     * valid fingerprint in this line. */
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in vote.");
    }
    ParseHelper.parseTwentyByteHexString(line, parts[1]);
  }

  private void parseLegacyDirKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.legacyDirKey = ParseHelper.parseTwentyByteHexString(line,
        parts[1]);
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

  private void parseDirIdentityKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-identity-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirSigningKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-signing-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirKeyCrosscertLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-key-crosscert")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirKeyCertificationLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-key-certification")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  protected void parseFooter(byte[] footerBytes)
      throws DescriptorParseException {
    Scanner scanner = new Scanner(new String(footerBytes)).useDelimiter("\n");
    while (scanner.hasNext()) {
      String line = scanner.next();
      if (!line.equals("directory-footer")) {
        if (this.failUnrecognizedDescriptorLines) {
          throw new DescriptorParseException("Unrecognized line '"
              + line + "' in vote.");
        } else {
          if (this.unrecognizedLines == null) {
            this.unrecognizedLines = new ArrayList<>();
          }
          this.unrecognizedLines.add(line);
        }
      }
    }
  }

  private String nickname;

  @Override
  public String getNickname() {
    return this.nickname;
  }

  private String identity;

  @Override
  public String getIdentity() {
    return this.identity;
  }

  private String hostname;

  @Override
  public String getHostname() {
    return this.hostname;
  }

  private String address;

  @Override
  public String getAddress() {
    return this.address;
  }

  private int dirPort;

  @Override
  public int getDirport() {
    return this.dirPort;
  }

  private int orPort;

  @Override
  public int getOrport() {
    return this.orPort;
  }

  private String contactLine;

  @Override
  public String getContactLine() {
    return this.contactLine;
  }

  private boolean sharedRandParticipate = false;

  @Override
  public boolean isSharedRandParticipate() {
    return this.sharedRandParticipate;
  }

  private List<String> sharedRandCommitLines = null;

  @Override
  public List<String> getSharedRandCommitLines() {
    return this.sharedRandCommitLines;
  }

  private int sharedRandPreviousNumReveals = -1;

  @Override
  public int getSharedRandPreviousNumReveals() {
    return this.sharedRandPreviousNumReveals;
  }

  private String sharedRandPreviousValue = null;

  @Override
  public String getSharedRandPreviousValue() {
    return this.sharedRandPreviousValue;
  }

  private int sharedRandCurrentNumReveals = -1;

  @Override
  public int getSharedRandCurrentNumReveals() {
    return this.sharedRandCurrentNumReveals;
  }

  private String sharedRandCurrentValue = null;

  @Override
  public String getSharedRandCurrentValue() {
    return this.sharedRandCurrentValue;
  }

  private int dirKeyCertificateVersion;

  @Override
  public int getDirKeyCertificateVersion() {
    return this.dirKeyCertificateVersion;
  }

  private String legacyDirKey;

  @Override
  public String getLegacyDirKey() {
    return this.legacyDirKey;
  }

  private long dirKeyPublishedMillis;

  @Override
  public long getDirKeyPublishedMillis() {
    return this.dirKeyPublishedMillis;
  }

  private long dirKeyExpiresMillis;

  @Override
  public long getDirKeyExpiresMillis() {
    return this.dirKeyExpiresMillis;
  }

  private String dirIdentityKey;

  @Override
  public String getDirIdentityKey() {
    return this.dirIdentityKey;
  }

  private String dirSigningKey;

  @Override
  public String getDirSigningKey() {
    return this.dirSigningKey;
  }

  private String dirKeyCrosscert;

  @Override
  public String getDirKeyCrosscert() {
    return this.dirKeyCrosscert;
  }

  private String dirKeyCertification;

  @Override
  public String getDirKeyCertification() {
    return this.dirKeyCertification;
  }

  @Override
  public String getSigningKeyDigest() {
    String signingKeyDigest = null;
    if (this.signatures != null && !this.signatures.isEmpty()) {
      for (DirectorySignature signature : this.signatures) {
        if (DirectorySignatureImpl.DEFAULT_ALGORITHM.equals(
            signature.getAlgorithm())) {
          signingKeyDigest = signature.getSigningKeyDigest();
          break;
        }
      }
    }
    return signingKeyDigest;
  }

  private int networkStatusVersion;

  @Override
  public int getNetworkStatusVersion() {
    return this.networkStatusVersion;
  }

  private Integer[] consensusMethods;

  @Override
  public List<Integer> getConsensusMethods() {
    return this.consensusMethods == null ? null
        : Arrays.asList(this.consensusMethods);
  }

  private long publishedMillis;

  @Override
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private long validAfterMillis;

  @Override
  public long getValidAfterMillis() {
    return this.validAfterMillis;
  }

  private long freshUntilMillis;

  @Override
  public long getFreshUntilMillis() {
    return this.freshUntilMillis;
  }

  private long validUntilMillis;

  @Override
  public long getValidUntilMillis() {
    return this.validUntilMillis;
  }

  private long voteSeconds;

  @Override
  public long getVoteSeconds() {
    return this.voteSeconds;
  }

  private long distSeconds;

  @Override
  public long getDistSeconds() {
    return this.distSeconds;
  }

  private String[] recommendedClientVersions;

  @Override
  public List<String> getRecommendedClientVersions() {
    return this.recommendedClientVersions == null ? null
        : Arrays.asList(this.recommendedClientVersions);
  }

  private String[] recommendedServerVersions;

  @Override
  public List<String> getRecommendedServerVersions() {
    return this.recommendedServerVersions == null ? null
        : Arrays.asList(this.recommendedServerVersions);
  }

  private SortedMap<String, SortedSet<Long>> recommendedClientProtocols;

  @Override
  public SortedMap<String, SortedSet<Long>> getRecommendedClientProtocols() {
    return this.recommendedClientProtocols;
  }

  private SortedMap<String, SortedSet<Long>> recommendedRelayProtocols;

  @Override
  public SortedMap<String, SortedSet<Long>> getRecommendedRelayProtocols() {
    return this.recommendedRelayProtocols;
  }

  private SortedMap<String, SortedSet<Long>> requiredClientProtocols;

  @Override
  public SortedMap<String, SortedSet<Long>> getRequiredClientProtocols() {
    return this.requiredClientProtocols;
  }

  private SortedMap<String, SortedSet<Long>> requiredRelayProtocols;

  @Override
  public SortedMap<String, SortedSet<Long>> getRequiredRelayProtocols() {
    return this.requiredRelayProtocols;
  }

  private List<String> packageLines;

  @Override
  public List<String> getPackageLines() {
    return this.packageLines == null ? null
        : new ArrayList<>(this.packageLines);
  }

  private String[] knownFlags;

  @Override
  public SortedSet<String> getKnownFlags() {
    return new TreeSet<>(Arrays.asList(this.knownFlags));
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

  private SortedMap<String, Integer> consensusParams;

  @Override
  public SortedMap<String, Integer> getConsensusParams() {
    return this.consensusParams == null ? null
        : new TreeMap<>(this.consensusParams);
  }
}

