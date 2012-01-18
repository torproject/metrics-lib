/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeSet;
import org.torproject.descriptor.NetworkStatusEntry;

public class NetworkStatusEntryImpl implements NetworkStatusEntry {

  private byte[] statusEntryBytes;
  public byte[] getStatusEntryBytes() {
    return this.statusEntryBytes;
  }

  protected NetworkStatusEntryImpl(byte[] statusEntryBytes)
      throws DescriptorParseException {
    this.statusEntryBytes = statusEntryBytes;
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
    this.atMostOnceKeywords.add("m");
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
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.statusEntryBytes)));
      String line = br.readLine();
      if (line == null || !line.startsWith("r ")) {
        throw new DescriptorParseException("Status entry must start with "
            + "an r line.");
      }
      String[] rLineParts = line.split(" ");
      this.parseRLine(line, rLineParts);
      while ((line = br.readLine()) != null) {
        String[] parts = !line.startsWith("opt ") ? line.split(" ") :
            line.substring("opt ".length()).split(" ");
        String keyword = parts[0];
        if (keyword.equals("s")) {
          this.parseSLine(line, parts);
        } else if (keyword.equals("v")) {
          this.parseVLine(line, parts);
        } else if (keyword.equals("w")) {
          this.parseWLine(line, parts);
        } else if (keyword.equals("p")) {
          this.parsePLine(line, parts);
        } else if (keyword.equals("m")) {
          this.parseMLine(line, parts);
        } else {
          /* TODO Is throwing an exception the right thing to do here?
           * This is probably fine for development, but once the library
           * is in production use, this seems annoying. */
          throw new DescriptorParseException("Unknown line '" + line
              + "' in status entry.");
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  private void parseRLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 9) {
      throw new RuntimeException("r line '" + line + "' has fewer "
          + "space-separated elements than expected.");
    }
    this.nickname = ParseHelper.parseNickname(line, parts[1]);
    this.fingerprint = ParseHelper.parseTwentyByteBase64String(line,
        parts[2]);
    this.descriptor = ParseHelper.parseTwentyByteBase64String(line,
        parts[3]);
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        4, 5);
    this.address = ParseHelper.parseIpv4Address(line, parts[6]);
    this.orPort = ParseHelper.parsePort(line, parts[7]);
    this.dirPort = ParseHelper.parsePort(line, parts[8]);
  }

  private void parseSLine(String line, String[] parts)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("s");
    this.flags = new TreeSet<String>();
    for (int i = 1; i < parts.length; i++) {
      this.flags.add(parts[i]);
    }
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
    SortedMap<String, Integer> pairs = ParseHelper.parseKeyValuePairs(
        line, parts, 1);
    if (pairs.isEmpty()) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    if (pairs.containsKey("Bandwidth")) {
      this.bandwidth = pairs.remove("Bandwidth");
    }
    if (pairs.containsKey("Measured")) {
      this.measured = pairs.remove("Measured");
    }
    if (!pairs.isEmpty()) {
      throw new DescriptorParseException("Unknown key-value pair in "
          + "line '" + line + "'.");
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
    this.parsedAtMostOnceKeyword("m");
    /* TODO Implement parsing of m lines in votes.  Try to find where m
     * lines are specified first. */
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

  private SortedSet<String> flags;
  public SortedSet<String> getFlags() {
    return new TreeSet<String>(this.flags);
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

  private String defaultPolicy;
  public String getDefaultPolicy() {
    return this.defaultPolicy;
  }

  private String portList;
  public String getPortList() {
    return this.portList;
  }
}

