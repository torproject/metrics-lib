/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.TimeZone;

import org.torproject.descriptor.ExitList;
import org.torproject.descriptor.ExitListEntry;

/* TODO Add test class. */
public class ExitListImpl extends DescriptorImpl implements ExitList {

  protected ExitListImpl(byte[] rawDescriptorBytes, String fileName,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(rawDescriptorBytes, failUnrecognizedDescriptorLines, false);
    this.splitAndParseExitListEntries(rawDescriptorBytes);
    this.setPublishedMillisFromFileName(fileName);
  }

  private void setPublishedMillisFromFileName(String fileName)
      throws DescriptorParseException {
    if (this.downloadedMillis == 0L &&
        fileName.length() == "2012-02-01-04-06-24".length()) {
      try {
        SimpleDateFormat fileNameFormat = new SimpleDateFormat(
            "yyyy-MM-dd-HH-mm-ss");
        fileNameFormat.setLenient(false);
        fileNameFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
        this.downloadedMillis = fileNameFormat.parse(fileName).getTime();
      } catch (ParseException e) {
        /* Handle below. */
      }
    }
    if (this.downloadedMillis == 0L) {
      throw new DescriptorParseException("Unrecognized exit list file "
          + "name '" + fileName + "'.");
    }
  }

  private void splitAndParseExitListEntries(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    if (this.rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    String descriptorString = new String(rawDescriptorBytes);
    Scanner s = new Scanner(descriptorString).useDelimiter("\n");
    StringBuilder sb = new StringBuilder();
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ");
      String keyword = parts[0];
      if (keyword.equals("Downloaded")) {
        this.downloadedMillis = ParseHelper.parseTimestampAtIndex(line,
            parts, 1, 2);
      } else if (keyword.equals("ExitNode")) {
        sb = new StringBuilder();
        sb.append(line + "\n");
      } else if (keyword.equals("Published")) {
        sb.append(line + "\n");
      } else if (keyword.equals("LastStatus")) {
        sb.append(line + "\n");
      } else if (keyword.equals("ExitAddress")) {
        String exitListEntryString = sb.toString() + line + "\n";
        byte[] exitListEntryBytes = exitListEntryString.getBytes();
        this.parseExitListEntry(exitListEntryBytes);
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in exit list.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<String>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  protected void parseExitListEntry(byte[] exitListEntryBytes)
      throws DescriptorParseException {
    ExitListEntryImpl exitListEntry = new ExitListEntryImpl(
        exitListEntryBytes, this.failUnrecognizedDescriptorLines);
    this.exitListEntries.add(exitListEntry);
    List<String> unrecognizedExitListEntryLines = exitListEntry.
        getAndClearUnrecognizedLines();
    if (unrecognizedExitListEntryLines != null) {
      if (this.unrecognizedLines == null) {
        this.unrecognizedLines = new ArrayList<String>();
      }
      this.unrecognizedLines.addAll(unrecognizedExitListEntryLines);
    }
  }

  private long downloadedMillis;
  public long getDownloadedMillis() {
    return this.downloadedMillis;
  }

  private Set<ExitListEntry> exitListEntries =
      new HashSet<ExitListEntry>();
  public Set<ExitListEntry> getExitListEntries() {
    return new HashSet<ExitListEntry>(this.exitListEntries);
  }
}

