/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import org.apache.commons.codec.digest.DigestUtils;
import org.torproject.descriptor.RelayNetworkStatus;

/* TODO Write unit tests. */

public class RelayNetworkStatusImpl extends NetworkStatusImpl
    implements RelayNetworkStatus {

  protected static List<RelayNetworkStatus> parseStatuses(
      byte[] statusesBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<RelayNetworkStatus> parsedStatuses =
        new ArrayList<RelayNetworkStatus>();
    List<byte[]> splitStatusBytes =
        DescriptorImpl.splitRawDescriptorBytes(statusesBytes,
        "network-status-version 2");
    for (byte[] statusBytes : splitStatusBytes) {
      RelayNetworkStatus parsedStatus = new RelayNetworkStatusImpl(
          statusBytes, failUnrecognizedDescriptorLines);
      parsedStatuses.add(parsedStatus);
    }
    return parsedStatuses;
  }

  protected RelayNetworkStatusImpl(byte[] statusBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(statusBytes, failUnrecognizedDescriptorLines, false, true);
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList((
        "network-status-version,dir-source,fingerprint,contact,"
        + "dir-signing-key,published").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList(
        "dir-options,client-versions,server-versions".split(",")));
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
      sig = ascii.indexOf("\n", sig) + 1;
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, sig - start);
        this.statusDigest = DigestUtils.shaHex(forDigest);
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    }
    if (this.statusDigest == null) {
      throw new DescriptorParseException("Could not calculate status "
          + "digest.");
    }
  }

  protected void parseHeader(byte[] headerBytes)
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(headerBytes)).useDelimiter("\n");
    String nextCrypto = null;
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      if (line.isEmpty()) {
        continue;
      }
      String[] parts = line.split(" ");
      String keyword = parts[0];
      if (keyword.equals("network-status-version")) {
        this.parseNetworkStatusVersionLine(line, parts);
      } else if (keyword.equals("dir-source")) {
        this.parseDirSourceLine(line, parts);
      } else if (keyword.equals("fingerprint")) {
        this.parseFingerprintLine(line, parts);
      } else if (keyword.equals("contact")) {
        this.parseContactLine(line, parts);
      } else if (keyword.equals("dir-signing-key")) {
        this.parseDirSigningKeyLine(line, parts);
        nextCrypto = "dir-signing-key";
      } else if (keyword.equals("client-versions")) {
        this.parseClientVersionsLine(line, parts);
      } else if (keyword.equals("server-versions")) {
        this.parseServerVersionsLine(line, parts);
      } else if (keyword.equals("published")) {
        this.parsePublishedLine(line, parts);
      } else if (keyword.equals("dir-options")) {
        this.parseDirOptionsLine(line, parts);
      } else if (line.startsWith("-----BEGIN")) {
        crypto = new StringBuilder();
        crypto.append(line + "\n");
      } else if (line.startsWith("-----END")) {
        crypto.append(line + "\n");
        String cryptoString = crypto.toString();
        crypto = null;
        if (nextCrypto.equals("dir-signing-key")) {
          this.dirSigningKey = cryptoString;
        } else {
          throw new DescriptorParseException("Unrecognized crypto "
              + "block in v2 network status.");
        }
        nextCrypto = null;
      } else if (crypto != null) {
        crypto.append(line + "\n");
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in v2 network status.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<String>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  protected void parseFooter(byte[] footerBytes)
      throws DescriptorParseException {
    throw new DescriptorParseException("No directory footer expected in "
        + "v2 network status.");
  }

  protected void parseDirectorySignature(byte[] directorySignatureBytes)
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(directorySignatureBytes)).
        useDelimiter("\n");
    String nextCrypto = null;
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ");
      String keyword = parts[0];
      if (keyword.equals("directory-signature")) {
        this.parseDirectorySignatureLine(line, parts);
        nextCrypto = "directory-signature";
      } else if (line.startsWith("-----BEGIN")) {
        crypto = new StringBuilder();
        crypto.append(line + "\n");
      } else if (line.startsWith("-----END")) {
        crypto.append(line + "\n");
        String cryptoString = crypto.toString();
        crypto = null;
        if (nextCrypto.equals("directory-signature")) {
          this.directorySignature = cryptoString;
        } else {
          throw new DescriptorParseException("Unrecognized crypto "
              + "block in v2 network status.");
        }
        nextCrypto = null;
      } else if (crypto != null) {
        crypto.append(line + "\n");
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in v2 network status.");
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
    if (!line.equals("network-status-version 2")) {
      throw new DescriptorParseException("Illegal network status version "
          + "number in line '" + line + "'.");
    }
    this.networkStatusVersion = 2;
  }

  private void parseDirSourceLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 4) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in v2 network status.");
    }
    if (parts[1].length() < 1) {
      throw new DescriptorParseException("Illegal hostname in '" + line
          + "'.");
    }
    this.address = ParseHelper.parseIpv4Address(line, parts[2]);
    this.dirPort = ParseHelper.parsePort(line, parts[3]);
  }


  private void parseFingerprintLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in v2 network status.");
    }
    this.fingerprint = ParseHelper.parseTwentyByteHexString(line,
        parts[1]);
  }

  private void parseContactLine(String line, String[] parts)
      throws DescriptorParseException {
    if (line.length() > "contact ".length()) {
      this.contactLine = line.substring("contact ".length());
    } else {
      this.contactLine = "";
    }
  }

  private void parseDirSigningKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-signing-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
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

  private void parsePublishedLine(String line, String[] parts)
      throws DescriptorParseException {
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseDirOptionsLine(String line, String[] parts)
      throws DescriptorParseException {
    this.dirOptions = new TreeSet<String>();
    for (int i = 1; i < parts.length; i++) {
      this.dirOptions.add(parts[i]);
    }
  }

  private void parseDirectorySignatureLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.nickname = ParseHelper.parseNickname(line, parts[1]);
  }

  private String statusDigest;
  public String getStatusDigest() {
    return this.statusDigest;
  }

  private int networkStatusVersion;
  public int getNetworkStatusVersion() {
    return this.networkStatusVersion;
  }

  private String hostname;
  public String getHostname() {
    return this.hostname;
  }

  private String address;
  public String getAddress() {
    return this.address;
  }

  private int dirPort;
  public int getDirport() {
    return this.dirPort;
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private String contactLine;
  public String getContactLine() {
    return this.contactLine;
  }

  private String dirSigningKey;
  public String getDirSigningKey() {
    return this.dirSigningKey;
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

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private SortedSet<String> dirOptions;
  public SortedSet<String> getDirOptions() {
    return new TreeSet<String>(this.dirOptions);
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String directorySignature;
  public String getDirectorySignature() {
    return this.directorySignature;
  }
}

