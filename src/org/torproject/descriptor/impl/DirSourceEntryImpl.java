/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import java.util.SortedSet;
import java.util.TreeSet;
import org.torproject.descriptor.DirSourceEntry;

public class DirSourceEntryImpl implements DirSourceEntry {

  private byte[] dirSourceEntryBytes;
  public byte[] getDirSourceEntryBytes() {
    return this.dirSourceEntryBytes;
  }

  protected DirSourceEntryImpl(byte[] dirSourceEntryBytes)
      throws DescriptorParseException {
    this.dirSourceEntryBytes = dirSourceEntryBytes;
    this.initializeKeywords();
    this.parseDirSourceEntryBytes();
    this.checkKeywords();
  }

  private SortedSet<String> exactlyOnceKeywords, atMostOnceKeywords;
  private void initializeKeywords() {
    this.exactlyOnceKeywords = new TreeSet<String>();
    this.exactlyOnceKeywords.add("dir-source");
    this.exactlyOnceKeywords.add("vote-digest");
    this.atMostOnceKeywords = new TreeSet<String>();
    this.atMostOnceKeywords.add("contact");
  }

  private void parsedExactlyOnceKeyword(String keyword)
      throws DescriptorParseException {
    if (!this.exactlyOnceKeywords.contains(keyword)) {
      throw new DescriptorParseException("Duplicate '" + keyword
          + "' line in dir-source.");
    }
    this.exactlyOnceKeywords.remove(keyword);
  }

  private void parsedAtMostOnceKeyword(String keyword)
      throws DescriptorParseException {
    if (!this.atMostOnceKeywords.contains(keyword)) {
      throw new DescriptorParseException("Duplicate " + keyword + "line "
          + "in dir-source.");
    }
    this.atMostOnceKeywords.remove(keyword);
  }

  private void checkKeywords() throws DescriptorParseException {
    if (!this.exactlyOnceKeywords.isEmpty()) {
      throw new DescriptorParseException("dir-source does not contain a '"
          + this.exactlyOnceKeywords.first() + "' line.");
    }
  }

  private void parseDirSourceEntryBytes()
      throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.dirSourceEntryBytes)));
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("dir-source")) {
          this.parseDirSourceLine(line);
        } else if (line.startsWith("contact")) {
          this.parseContactLine(line);
        } else if (line.startsWith("vote-digest")) {
          this.parseVoteDigestLine(line);
        } else {
          /* TODO Should we really throw an exception here? */
          throw new DescriptorParseException("Unknown line '" + line
              + "' in dir-source entry.");
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  private void parseDirSourceLine(String line)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("dir-source");
    String[] parts = line.split(" ");
    String nickname = parts[1];
    if (nickname.endsWith("-legacy")) {
      nickname = nickname.substring(0, nickname.length()
          - "-legacy".length());
      this.isLegacy = true;
      this.parsedExactlyOnceKeyword("vote-digest");
    }
    this.nickname = ParseHelper.parseNickname(line, nickname);
    this.identity = ParseHelper.parseTwentyByteHexString(line, parts[2]);
    this.ip = ParseHelper.parseIpv4Address(line, parts[4]);
    this.dirPort = ParseHelper.parsePort(line, parts[5]);
    this.orPort = ParseHelper.parsePort(line, parts[6]);
  }

  private void parseContactLine(String line)
      throws DescriptorParseException {
    this.parsedAtMostOnceKeyword("contact");
    if (line.length() > "contact ".length()) {
      this.contactLine = line.substring("contact ".length());
    } else {
      this.contactLine = "";
    }
  }

  private void parseVoteDigestLine(String line)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("vote-digest");
    String[] parts = line.split(" ");
    if (parts.length != 2) {
      throw new DescriptorParseException("Invalid line '" + line + "'.");
    }
    this.voteDigest = ParseHelper.parseTwentyByteHexString(line,
        parts[1]);
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String identity;
  public String getIdentity() {
    return this.identity;
  }

  private boolean isLegacy;
  public boolean isLegacy() {
    return this.isLegacy;
  }

  private String ip;
  public String getIp() {
    return this.ip;
  }

  private int dirPort;
  public int getDirPort() {
    return this.dirPort;
  }

  private int orPort;
  public int getOrPort() {
    return this.orPort;
  }

  private String contactLine;
  public String getContactLine() {
    return this.contactLine;
  }

  private String voteDigest;
  public String getVoteDigest() {
    return this.voteDigest;
  }
}

