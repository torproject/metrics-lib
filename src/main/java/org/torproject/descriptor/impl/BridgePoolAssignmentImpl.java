/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.BridgePoolAssignment;
import org.torproject.descriptor.DescriptorParseException;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Scanner;
import java.util.SortedMap;
import java.util.TreeMap;

public class BridgePoolAssignmentImpl extends DescriptorImpl
    implements BridgePoolAssignment {

  protected static List<BridgePoolAssignment> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<BridgePoolAssignment> parsedDescriptors = new ArrayList<>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP);
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      BridgePoolAssignment parsedDescriptor =
          new BridgePoolAssignmentImpl(descriptorBytes,
              failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected BridgePoolAssignmentImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseDescriptorBytes();
    this.checkExactlyOnceKeys(EnumSet.of(Key.BRIDGE_POOL_ASSIGNMENT));
    this.checkFirstKey(Key.BRIDGE_POOL_ASSIGNMENT);
    this.clearParsedKeys();
    return;
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    Scanner scanner = new Scanner(new String(this.rawDescriptorBytes))
        .useDelimiter(NL);
    while (scanner.hasNext()) {
      String line = scanner.next();
      if (line.startsWith(Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP)) {
        this.parseBridgePoolAssignmentLine(line);
      } else {
        this.parseBridgeLine(line);
      }
    }
  }

  private void parseBridgePoolAssignmentLine(String line)
      throws DescriptorParseException {
    String[] parts = line.split("[ \t]+");
    if (parts.length != 3) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in bridge pool assignment.");
    }
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line,
        parts, 1, 2);
  }

  private void parseBridgeLine(String line)
      throws DescriptorParseException {
    String[] parts = line.split("[ \t]+");
    if (parts.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in bridge pool assignment.");
    }
    String fingerprint = ParseHelper.parseTwentyByteHexString(line,
        parts[0]);
    String poolAndDetails = line.substring(line.indexOf(SP) + 1);
    this.entries.put(fingerprint, poolAndDetails);
  }

  private long publishedMillis;

  @Override
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private SortedMap<String, String> entries = new TreeMap<>();

  @Override
  public SortedMap<String, String> getEntries() {
    return new TreeMap<>(this.entries);
  }
}

