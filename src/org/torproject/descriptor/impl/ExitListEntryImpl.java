/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.SortedSet;
import java.util.TreeSet;

import org.torproject.descriptor.ExitListEntry;

public class ExitListEntryImpl implements ExitListEntry {

  private byte[] exitListEntryBytes;
  public byte[] getExitListEntryBytes() {
    return this.exitListEntryBytes;
  }

  private boolean failUnrecognizedDescriptorLines;
  private List<String> unrecognizedLines;
  protected List<String> getAndClearUnrecognizedLines() {
    List<String> lines = this.unrecognizedLines;
    this.unrecognizedLines = null;
    return lines;
  }

  protected ExitListEntryImpl(byte[] exitListEntryBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    this.exitListEntryBytes = exitListEntryBytes;
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
    this.initializeKeywords();
    this.parseExitListEntryBytes();
    this.checkAndClearKeywords();
  }

  private SortedSet<String> exactlyOnceKeywords;
  private void initializeKeywords() {
    this.exactlyOnceKeywords = new TreeSet<String>();
    this.exactlyOnceKeywords.add("ExitNode");
    this.exactlyOnceKeywords.add("Published");
    this.exactlyOnceKeywords.add("LastStatus");
    this.exactlyOnceKeywords.add("ExitAddress");
  }

  private void parsedExactlyOnceKeyword(String keyword)
      throws DescriptorParseException {
    if (!this.exactlyOnceKeywords.contains(keyword)) {
      throw new DescriptorParseException("Duplicate '" + keyword
          + "' line in exit list entry.");
    }
    this.exactlyOnceKeywords.remove(keyword);
  }

  private void checkAndClearKeywords() throws DescriptorParseException {
    for (String missingKeyword : this.exactlyOnceKeywords) {
      throw new DescriptorParseException("Missing '" + missingKeyword
          + "' line in exit list entry.");
    }
    this.exactlyOnceKeywords = null;
  }

  private void parseExitListEntryBytes()
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.exitListEntryBytes)).
        useDelimiter("\n");
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ");
      String keyword = parts[0];
      if (keyword.equals("ExitNode")) {
        this.parseExitNodeLine(line, parts);
      } else if (keyword.equals("Published")) {
        this.parsePublishedLine(line, parts);
      } else if (keyword.equals("LastStatus")) {
        this.parseLastStatusLine(line, parts);
      } else if (keyword.equals("ExitAddress")) {
        this.parseExitAddressLine(line, parts);
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in exit list entry.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<String>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  private void parseExitNodeLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Invalid line '" + line + "' in "
          + "exit list entry.");
    }
    this.parsedExactlyOnceKeyword(parts[0]);
    this.fingerprint = ParseHelper.parseTwentyByteHexString(line,
        parts[1]);
  }

  private void parsePublishedLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 3) {
      throw new DescriptorParseException("Invalid line '" + line + "' in "
          + "exit list entry.");
    }
    this.parsedExactlyOnceKeyword(parts[0]);
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseLastStatusLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 3) {
      throw new DescriptorParseException("Invalid line '" + line + "' in "
          + "exit list entry.");
    }
    this.parsedExactlyOnceKeyword(parts[0]);
    this.lastStatusMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        1, 2);
  }

  private void parseExitAddressLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 4) {
      throw new DescriptorParseException("Invalid line '" + line + "' in "
          + "exit list entry.");
    }
    this.parsedExactlyOnceKeyword(parts[0]);
    this.exitAddress = ParseHelper.parseIpv4Address(line, parts[1]);
    this.scanMillis = ParseHelper.parseTimestampAtIndex(line, parts,
        2, 3);
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private long lastStatusMillis;
  public long getLastStatusMillis() {
    return this.lastStatusMillis;
  }

  private String exitAddress;
  public String getExitAddress() {
    return this.exitAddress;
  }

  private long scanMillis;
  public long getScanMillis() {
    return this.scanMillis;
  }
}

