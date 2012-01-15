/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import org.torproject.descriptor.BridgePoolAssignment;

/* TODO Write a test class. */
public class BridgePoolAssignmentImpl extends DescriptorImpl
    implements BridgePoolAssignment {

  protected static List<BridgePoolAssignment> parseDescriptors(
      byte[] descriptorsBytes) {
    List<BridgePoolAssignment> parsedDescriptors =
        new ArrayList<BridgePoolAssignment>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "bridge-pool-assignment ");
    try {
      for (byte[] descriptorBytes : splitDescriptorsBytes) {
        BridgePoolAssignment parsedDescriptor =
            new BridgePoolAssignmentImpl(descriptorBytes);
        parsedDescriptors.add(parsedDescriptor);
      }
    } catch (DescriptorParseException e) {
      /* TODO Handle this error somehow. */
      System.err.println("Failed to parse descriptor.  Skipping.");
      e.printStackTrace();
    }
    return parsedDescriptors;
  }

  protected BridgePoolAssignmentImpl(byte[] descriptorBytes)
      throws DescriptorParseException {
    super(descriptorBytes);
    this.parseDescriptorBytes();
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList(
        new String[] { "bridge-pool-assignment" }));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    this.checkFirstKeyword("bridge-pool-assignment");
    return;
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.rawDescriptorBytes)));
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("bridge-pool-assignment ")) {
          this.parseBridgePoolAssignmentLine(line);
        } else {
          this.parseBridgeLine(line);
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  private void parseBridgePoolAssignmentLine(String line)
      throws DescriptorParseException {
    String[] parts = line.split(" ");
    if (parts.length != 3) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in bridge pool assignment.");
    }
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line,
        parts, 1, 2);
  }

  private void parseBridgeLine(String line) 
      throws DescriptorParseException {
    String[] parts = line.split(" ");
    if (parts.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in bridge pool assignment.");
    }
    String fingerprint = ParseHelper.parseTwentyByteHexString(line,
        parts[0]);
    String poolAndDetails = line.substring(line.indexOf(" ") + 1);
    this.entries.put(fingerprint, poolAndDetails);
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private SortedMap<String, String> entries =
      new TreeMap<String, String>();
  public SortedMap<String, String> getEntries() {
    return new TreeMap<String, String>(this.entries);
  }
}

