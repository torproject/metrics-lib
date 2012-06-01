/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;
import java.util.SortedMap;
import java.util.TreeMap;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.GetTorStatistics;

public class GetTorStatisticsImpl extends DescriptorImpl
    implements GetTorStatistics {

  public static List<Descriptor> parseGetTorStatistics(
      byte[] rawDescriptorBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    if (rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    List<Descriptor> parsedDescriptors = new ArrayList<Descriptor>();
    String descriptorString = new String(rawDescriptorBytes);
    Scanner s = new Scanner(descriptorString).useDelimiter("\n");
    while (s.hasNext()) {
      String line = s.next();
      if (line.startsWith("@type gettor ")) {
        String[] parts = line.split(" ");
        if (parts.length != 3) {
          throw new DescriptorParseException("Illegal line '" + line
              + "'.");
        }
        String version = parts[2];
        if (!version.startsWith("1.")) {
          throw new DescriptorParseException("Unsupported version in "
              + " line '" + line + "'.");
        }
      } else {
        parsedDescriptors.add(new GetTorStatisticsImpl(line.getBytes(),
            failUnrecognizedDescriptorLines));
      }
    }
    return parsedDescriptors;
  }

  protected GetTorStatisticsImpl(byte[] rawDescriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(rawDescriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseGetTorStatisticsLine(new String(rawDescriptorBytes));
  }

  private void parseGetTorStatisticsLine(String line)
      throws DescriptorParseException {
    if (line.isEmpty()) {
      throw new DescriptorParseException("Blank lines are not allowed.");
    }
    String[] parts = line.split(" ");
    if (parts.length < 3) {
      throw new DescriptorParseException("Illegal GetTor statistics line "
          + "'" + line + "'.");
    }
    this.dateMillis = ParseHelper.parseDateAtIndex(line, parts, 0);
    this.downloadedPackages = ParseHelper.parseKeyValuePairs(line, parts,
        2, ":");
  }

  private long dateMillis;
  public long getDateMillis() {
    return this.dateMillis;
  }

  private SortedMap<String, Integer> downloadedPackages;
  public SortedMap<String, Integer> getDownloadedPackages() {
    return new TreeMap<String, Integer>(this.downloadedPackages);
  }
}
