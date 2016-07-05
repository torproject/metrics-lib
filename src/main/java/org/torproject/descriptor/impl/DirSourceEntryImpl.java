/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.SortedSet;
import java.util.TreeSet;

import org.torproject.descriptor.DirSourceEntry;

public class DirSourceEntryImpl implements DirSourceEntry {

  private byte[] dirSourceEntryBytes;
  @Override
  public byte[] getDirSourceEntryBytes() {
    return this.dirSourceEntryBytes;
  }

  private boolean failUnrecognizedDescriptorLines;
  private List<String> unrecognizedLines;
  protected List<String> getAndClearUnrecognizedLines() {
    List<String> lines = this.unrecognizedLines;
    this.unrecognizedLines = null;
    return lines;
  }

  protected DirSourceEntryImpl(byte[] dirSourceEntryBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    this.dirSourceEntryBytes = dirSourceEntryBytes;
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
    this.initializeKeywords();
    this.parseDirSourceEntryBytes();
    this.checkAndClearKeywords();
  }

  private SortedSet<String> exactlyOnceKeywords, atMostOnceKeywords;
  private void initializeKeywords() {
    this.exactlyOnceKeywords = new TreeSet<>();
    this.exactlyOnceKeywords.add("dir-source");
    this.exactlyOnceKeywords.add("vote-digest");
    this.atMostOnceKeywords = new TreeSet<>();
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

  private void checkAndClearKeywords() throws DescriptorParseException {
    if (!this.exactlyOnceKeywords.isEmpty()) {
      throw new DescriptorParseException("dir-source does not contain a '"
          + this.exactlyOnceKeywords.first() + "' line.");
    }
    this.exactlyOnceKeywords = null;
    this.atMostOnceKeywords = null;
  }

  private void parseDirSourceEntryBytes()
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.dirSourceEntryBytes)).
        useDelimiter("\n");
    boolean skipCrypto = false;
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ");
      switch (parts[0]) {
      case "dir-source":
        this.parseDirSourceLine(line);
        break;
      case "contact":
        this.parseContactLine(line);
        break;
      case "vote-digest":
        this.parseVoteDigestLine(line);
        break;
      case "-----BEGIN":
        skipCrypto = true;
        break;
      case "-----END":
        skipCrypto = false;
        break;
      default:
        if (!skipCrypto) {
          if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized line '"
                + line + "' in dir-source entry.");
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

  private void parseDirSourceLine(String line)
      throws DescriptorParseException {
    this.parsedExactlyOnceKeyword("dir-source");
    String[] parts = line.split("[ \t]+");
    if (parts.length != 7) {
      throw new DescriptorParseException("Invalid line '" + line + "'.");
    }
    String nickname = parts[1];
    if (nickname.endsWith("-legacy")) {
      nickname = nickname.substring(0, nickname.length()
          - "-legacy".length());
      this.isLegacy = true;
      this.parsedExactlyOnceKeyword("vote-digest");
    }
    this.nickname = ParseHelper.parseNickname(line, nickname);
    this.identity = ParseHelper.parseTwentyByteHexString(line, parts[2]);
    if (parts[3].length() < 1) {
      throw new DescriptorParseException("Illegal hostname in '" + line
          + "'.");
    }
    this.hostname = parts[3];
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
    String[] parts = line.split("[ \t]+");
    if (parts.length != 2) {
      throw new DescriptorParseException("Invalid line '" + line + "'.");
    }
    this.voteDigest = ParseHelper.parseTwentyByteHexString(line,
        parts[1]);
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

  private boolean isLegacy;
  @Override
  public boolean isLegacy() {
    return this.isLegacy;
  }

  private String hostname;
  @Override
  public String getHostname() {
    return this.hostname;
  }

  private String ip;
  @Override
  public String getIp() {
    return this.ip;
  }

  private int dirPort;
  @Override
  public int getDirPort() {
    return this.dirPort;
  }

  private int orPort;
  @Override
  public int getOrPort() {
    return this.orPort;
  }

  private String contactLine;
  @Override
  public String getContactLine() {
    return this.contactLine;
  }

  private String voteDigest;
  @Override
  public String getVoteDigest() {
    return this.voteDigest;
  }
}

