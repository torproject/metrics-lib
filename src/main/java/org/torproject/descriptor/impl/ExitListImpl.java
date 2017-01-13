/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ExitList;
import org.torproject.descriptor.ExitListEntry;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.TimeZone;

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
    if (this.downloadedMillis == 0L
        && fileName.length() == "2012-02-01-04-06-24".length()) {
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
    Scanner scanner = new Scanner(descriptorString).useDelimiter(EOL);
    StringBuilder sb = new StringBuilder();
    boolean firstEntry = true;
    while (scanner.hasNext()) {
      String line = scanner.next();
      if (line.startsWith("@")) { /* Skip annotation. */
        if (!scanner.hasNext()) {
          throw new DescriptorParseException("Descriptor is empty.");
        } else {
          line = scanner.next();
        }
      }
      String[] parts = line.split(" ");
      String keyword = parts[0];
      switch (keyword) {
        case "Downloaded":
          this.downloadedMillis = ParseHelper.parseTimestampAtIndex(line,
              parts, 1, 2);
          break;
        case "ExitNode":
          if (!firstEntry) {
            this.parseExitListEntry(sb.toString().getBytes());
          } else {
            firstEntry = false;
          }
          sb = new StringBuilder();
          sb.append(line).append(ExitList.EOL);
          break;
        case "Published":
          sb.append(line).append(ExitList.EOL);
          break;
        case "LastStatus":
          sb.append(line).append(ExitList.EOL);
          break;
        case "ExitAddress":
          sb.append(line).append(ExitList.EOL);
          break;
        default:
          if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized line '"
                + line + "' in exit list.");
          } else {
            if (this.unrecognizedLines == null) {
              this.unrecognizedLines = new ArrayList<>();
            }
            this.unrecognizedLines.add(line);
          }
      }
    }
    /* Parse the last entry. */
    this.parseExitListEntry(sb.toString().getBytes());
  }

  protected void parseExitListEntry(byte[] exitListEntryBytes)
      throws DescriptorParseException {
    ExitListEntryImpl exitListEntry = new ExitListEntryImpl(
        exitListEntryBytes, this.failUnrecognizedDescriptorLines);
    this.exitListEntries.add(exitListEntry);
    this.oldExitListEntries.addAll(exitListEntry.oldEntries());
    List<String> unrecognizedExitListEntryLines = exitListEntry
        .getAndClearUnrecognizedLines();
    if (unrecognizedExitListEntryLines != null) {
      if (this.unrecognizedLines == null) {
        this.unrecognizedLines = new ArrayList<>();
      }
      this.unrecognizedLines.addAll(unrecognizedExitListEntryLines);
    }
  }

  private long downloadedMillis;

  @Override
  public long getDownloadedMillis() {
    return this.downloadedMillis;
  }

  private Set<ExitListEntry> oldExitListEntries = new HashSet<>();

  @Deprecated
  @Override
  public Set<ExitListEntry> getExitListEntries() {
    return new HashSet<>(this.oldExitListEntries);
  }

  private Set<ExitList.Entry> exitListEntries = new HashSet<>();

  @Override
  public Set<ExitList.Entry> getEntries() {
    return new HashSet<>(this.exitListEntries);
  }
}

