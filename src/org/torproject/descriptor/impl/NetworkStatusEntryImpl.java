/* Copyright 2011--2014 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeSet;

import org.torproject.descriptor.NetworkStatusEntry;

public class NetworkStatusEntryImpl implements NetworkStatusEntry {

  private byte[] statusEntryBytes;
  public byte[] getStatusEntryBytes() {
    return this.statusEntryBytes;
  }

  private boolean microdescConsensus;

  private boolean failUnrecognizedDescriptorLines;
  private List<String> unrecognizedLines;
  protected List<String> getAndClearUnrecognizedLines() {
    List<String> lines = this.unrecognizedLines;
    this.unrecognizedLines = null;
    return lines;
  }

  protected NetworkStatusEntryImpl(byte[] statusEntryBytes,
      boolean microdescConsensus, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    this.statusEntryBytes = statusEntryBytes;
    this.microdescConsensus = microdescConsensus;
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
    this.initializeKeywords();
    this.parseStatusEntryBytes();
  }

  private SortedSet<String> atMostOnceKeywords;
  private void initializeKeywords() {
    this.atMostOnceKeywords = new TreeSet<String>();
    this.atMostOnceKeywords.add("s");
    this.atMostOnceKeywords.add("v");
    this.atMostOnceKeywords.add("w");
    this.atMostOnceKeywords.add("p");
  }

  private void parsedAtMostOnceKeyword(String keyword)
      throws DescriptorParseException {
    if (!this.atMostOnceKeywords.contains(keyword)) {
      throw new DescriptorParseException("Duplicate '" + keyword
          + "' line in status entry.");
    }
    this.atMostOnceKeywords.remove(keyword);
  }

  private void parseStatusEntryBytes() throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.statusEntryBytes)).
        useDelimiter("\n");
    String line = null;
    if (!s.hasNext() || !(line = s.next()).startsWith("r ")) {
      throw new DescriptorParseException("Status entry must start with "
          + "an r line.");
    }
    String[] rLineParts = line.split(" ");
    this.parseRLine(line, rLineParts);
    while (s.hasNext()) {
      line = s.next();
      String[] parts = !line.startsWith("opt ") ? line.split(" ") :
          line.substring("opt ".length()).split(" ");
      String keyword = parts[0];
      if (keyword.equals("a")) {
        this.parseALine(line, parts);
      } else if (keyword.equals("s")) {
        this.parseSLine(line, parts);
      } else if (keyword.equals("v")) {
        this.parseVLine(line, parts);
      } else if (keyword.equals("w")) {
        this.parseWLine(line, parts);
      } else if (keyword.equals("p")) {
        this.parsePLine(line, parts);
      } else if (keyword.equals("m")) {
        this.parseMLine(line, parts);
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in status entry.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<String>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  private void parseRLine(String line, String[] parts)
      throws DescriptorParseException {
    if ((!this.microdescConsensus && parts.length != 9) ||
        (this.microdescConsensus && parts.length != 8)) {
      throw new DescriptorParseException("r line '" + line + "' has "
          + "fewer space-separated elements than expected.");
    }
    this.nickname = ParseHelper.parseNickname(line, parts[1]);
    this.fingerprint = ParseHelper.parseTwentyByteBase64String(line,
        parts[2]);
    int descriptorOffset = 0;
    if (!this.microdescConsensus) {
      this.descriptor = ParseHelper.parseTwentyByteBase64String(line,
          parts[3]);
      descriptorOffset = 1;
    }
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        3 + descriptorOffset, 4 + descriptorOffset);
    this.address = ParseHelper.parseIpv4Address(line,
        parts[5 + descriptorOffset]);
    this.orPort = ParseHelper.parsePort(line,
        parts[6 + descriptorOffset]);
    this.dirPort = ParseHelper.parsePort(line,
        parts[7 + descriptorOffset]);
  }

  private void parseALine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Invalid line '" + line + "' in "
          + "status entry.");
    }
    /* TODO Add more checks. */
    /* TODO Add tests. */
    this.orAddresses.add(parts[1]);
  }

  private void parseSLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("s");
    this.flags = parts;
  }

  private void parseVLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("v");
    String noOptLine = line;
    if (noOptLine.startsWith("opt ")) {
      noOptLine = noOptLine.substring(4);
    }
    if (noOptLine.length() < 3) {
      throw new DescriptorParseException("Invalid line '" + line + "' in "
          + "status entry.");
    } else {
      this.version = noOptLine.substring(2);
    }
  }

  private void parseWLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("w");
    SortedMap<String, Integer> pairs =
        ParseHelper.parseKeyValueIntegerPairs(line, parts, 1, "=");
    if (pairs.isEmpty()) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    if (pairs.containsKey("Bandwidth")) {
      this.bandwidth = pairs.remove("Bandwidth");
    }
    if (pairs.containsKey("Measured")) {
      this.measured = pairs.remove("Measured");
    }
    if (pairs.containsKey("Unmeasured")) {
      this.unmeasured = pairs.remove("Unmeasured") == 1L;
    }
    if (!pairs.isEmpty()) {
      /* Ignore unknown key-value pair. */
    }
  }

  private void parsePLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("p");
    boolean isValid = true;
    if (parts.length != 3) {
      isValid = false;
    } else if (!parts[1].equals("accept") && !parts[1].equals("reject")) {
      isValid = false;
    } else {
      this.defaultPolicy = parts[1];
      this.portList = parts[2];
      String[] ports = parts[2].split(",", -1);
      for (int i = 0; i < ports.length; i++) {
        if (ports[i].length() < 1) {
          isValid = false;
          break;
        }
      }
    }
    if (!isValid) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseMLine(String line, String[] parts)
      throws DescriptorParseException {
    if (this.microdescriptorDigests == null) {
      this.microdescriptorDigests = new HashSet<String>();
    }
    if (parts.length == 2) {
      this.microdescriptorDigests.add(
          ParseHelper.parseThirtyTwoByteBase64String(line, parts[1]));
    } else if (parts.length == 3 && parts[2].length() > 7) {
      /* 7 == "sha256=".length() */
      this.microdescriptorDigests.add(
          ParseHelper.parseThirtyTwoByteBase64String(line,
          parts[2].substring(7)));
    }
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private String descriptor;
  public String getDescriptor() {
    return this.descriptor;
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private String address;
  public String getAddress() {
    return this.address;
  }

  private int orPort;
  public int getOrPort() {
    return this.orPort;
  }

  private int dirPort;
  public int getDirPort() {
    return this.dirPort;
  }

  private Set<String> microdescriptorDigests;
  public Set<String> getMicrodescriptorDigests() {
    return this.microdescriptorDigests == null ? null :
        new HashSet<String>(this.microdescriptorDigests);
  }

  private List<String> orAddresses = new ArrayList<String>();
  public List<String> getOrAddresses() {
    return new ArrayList<String>(this.orAddresses);
  }

  private String[] flags;
  public SortedSet<String> getFlags() {
    SortedSet<String> result = new TreeSet<String>();
    if (this.flags != null) {
      for (int i = 1; i < this.flags.length; i++) {
        result.add(this.flags[i]);
      }
    }
    return result;
  }

  private String version;
  public String getVersion() {
    return this.version;
  }

  private long bandwidth = -1L;
  public long getBandwidth() {
    return this.bandwidth;
  }

  private long measured = -1L;
  public long getMeasured() {
    return this.measured;
  }

  private boolean unmeasured = false;
  public boolean getUnmeasured() {
    return this.unmeasured;
  }

  private String defaultPolicy;
  public String getDefaultPolicy() {
    return this.defaultPolicy;
  }

  private String portList;
  public String getPortList() {
    return this.portList;
  }
}

