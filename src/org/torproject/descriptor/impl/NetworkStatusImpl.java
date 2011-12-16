/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import org.torproject.descriptor.DirSourceEntry;
import org.torproject.descriptor.NetworkStatusEntry;

/* Parse the common parts of v3 consensuses, v3 votes, v3 microdesc
 * consensuses, v2 statuses, and sanitized bridge network statuses and
 * delegate the specific parts to the subclasses. */
public abstract class NetworkStatusImpl {

  protected static List<byte[]> splitRawDescriptorBytes(
      byte[] rawDescriptorBytes, String startToken) {
    List<byte[]> rawDescriptors = new ArrayList<byte[]>();
    String splitToken = "\n" + startToken;
    String ascii = new String(rawDescriptorBytes);
    int length = rawDescriptorBytes.length,
        start = ascii.indexOf(startToken);
    while (start < length) {
      int end = ascii.indexOf(splitToken, start);
      if (end < 0) {
        end = length;
      } else {
        end += 1;
      }
      byte[] rawDescriptor = new byte[end - start];
      System.arraycopy(rawDescriptorBytes, start, rawDescriptor, 0,
          end - start);
      start = end;
      rawDescriptors.add(rawDescriptor);
    }
    return rawDescriptors;
  }

  private byte[] rawDescriptorBytes;
  public byte[] getRawDescriptorBytes() {
    return this.rawDescriptorBytes;
  }

  protected NetworkStatusImpl(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    this.rawDescriptorBytes = rawDescriptorBytes;
    this.countKeywords(rawDescriptorBytes);
    this.splitAndParseParts(rawDescriptorBytes);
  }

  private void splitAndParseParts(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    if (this.rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    String descriptorString = new String(rawDescriptorBytes);
    if (descriptorString.startsWith("\n") ||
        descriptorString.contains("\n\n")) {
      throw new DescriptorParseException("Empty lines are not allowed.");
    }
    int startIndex = 0;
    int firstDirSourceIndex = this.findFirstIndexOfKeyword(
        descriptorString, "dir-source");
    int firstRIndex = this.findFirstIndexOfKeyword(descriptorString, "r");
    int directoryFooterIndex = this.findFirstIndexOfKeyword(
        descriptorString, "directory-footer");
    int firstDirectorySignatureIndex = this.findFirstIndexOfKeyword(
        descriptorString, "directory-signature");
    int endIndex = descriptorString.length();
    if (firstDirectorySignatureIndex < 0) {
      firstDirectorySignatureIndex = endIndex;
    }
    if (directoryFooterIndex < 0) {
      directoryFooterIndex = firstDirectorySignatureIndex;
    }
    if (firstRIndex < 0) {
      firstRIndex = directoryFooterIndex;
    }
    if (firstDirSourceIndex < 0) {
      firstDirSourceIndex = firstRIndex;
    }
    if (firstDirSourceIndex > startIndex) {
      this.parseHeaderBytes(descriptorString, startIndex,
          firstDirSourceIndex);
    }
    if (firstRIndex > firstDirSourceIndex) {
      this.parseDirSourceBytes(descriptorString, firstDirSourceIndex,
          firstRIndex);
    }
    if (directoryFooterIndex > firstRIndex) {
      this.parseStatusEntryBytes(descriptorString, firstRIndex,
          directoryFooterIndex);
    }
    if (firstDirectorySignatureIndex > directoryFooterIndex) {
      this.parseDirectoryFooterBytes(descriptorString,
          directoryFooterIndex, firstDirectorySignatureIndex);
    }
    if (endIndex > firstDirectorySignatureIndex) {
      this.parseDirectorySignatureBytes(descriptorString,
          firstDirectorySignatureIndex, endIndex);
    }
  }

  private int findFirstIndexOfKeyword(String descriptorString,
      String keyword) {
    if (descriptorString.startsWith(keyword)) {
      return 0;
    } else if (descriptorString.contains("\n" + keyword + " ")) {
      return descriptorString.indexOf("\n" + keyword + " ") + 1;
    } else if (descriptorString.contains("\n" + keyword + "\n")) {
      return descriptorString.indexOf("\n" + keyword + "\n") + 1;
    } else {
      return -1;
    }
  }

  private void parseHeaderBytes(String descriptorString, int start,
      int end) throws DescriptorParseException {
    byte[] headerBytes = new byte[end - start];
    System.arraycopy(this.rawDescriptorBytes, start,
        headerBytes, 0, end - start);
    this.rememberFirstKeyword(headerBytes);
    this.parseHeader(headerBytes);
  }

  private void parseDirSourceBytes(String descriptorString, int start,
      int end) throws DescriptorParseException {
    List<byte[]> splitDirSourceBytes =
        this.splitByKeyword(descriptorString, "dir-source", start, end);
    for (byte[] dirSourceBytes : splitDirSourceBytes) {
      this.parseDirSource(dirSourceBytes);
    }
  }

  private void parseStatusEntryBytes(String descriptorString, int start,
      int end) throws DescriptorParseException {
    List<byte[]> splitStatusEntryBytes =
        this.splitByKeyword(descriptorString, "r", start, end);
    for (byte[] statusEntryBytes : splitStatusEntryBytes) {
      this.parseStatusEntry(statusEntryBytes);
    }
  }

  private void parseDirectoryFooterBytes(String descriptorString,
      int start, int end) throws DescriptorParseException {
    byte[] directoryFooterBytes = new byte[end - start];
    System.arraycopy(this.rawDescriptorBytes, start,
        directoryFooterBytes, 0, end - start);
    this.parseFooter(directoryFooterBytes);
  }

  private void parseDirectorySignatureBytes(String descriptorString,
      int start, int end) throws DescriptorParseException {
    List<byte[]> splitDirectorySignatureBytes = this.splitByKeyword(
        descriptorString, "directory-signature", start, end);
    for (byte[] directorySignatureBytes : splitDirectorySignatureBytes) {
      this.parseDirectorySignature(directorySignatureBytes);
    }
  }

  private List<byte[]> splitByKeyword(String descriptorString,
      String keyword, int start, int end) {
    List<byte[]> splitParts = new ArrayList<byte[]>();
    int from = start;
    while (from < end) {
      int to = descriptorString.indexOf("\n" + keyword + " ", from);
      if (to < 0) {
        to = descriptorString.indexOf("\n" + keyword + "\n", from);
      }
      if (to < 0) {
        to = end;
      } else {
        to += 1;
      }
      byte[] part = new byte[to - from];
      System.arraycopy(this.rawDescriptorBytes, from, part, 0,
          to - from);
      from = to;
      splitParts.add(part);
    }
    return splitParts;
  }

  protected abstract void parseHeader(byte[] headerBytes)
      throws DescriptorParseException;

  protected void parseDirSource(byte[] dirSourceBytes)
      throws DescriptorParseException {
    DirSourceEntry dirSourceEntry = new DirSourceEntryImpl(
        dirSourceBytes);
    this.dirSourceEntries.put(dirSourceEntry.getIdentity(),
        dirSourceEntry);
  }

  protected void parseStatusEntry(byte[] statusEntryBytes)
      throws DescriptorParseException {
    NetworkStatusEntryImpl statusEntry = new NetworkStatusEntryImpl(
        statusEntryBytes);
    this.statusEntries.put(statusEntry.getFingerprint(), statusEntry);
  }

  protected abstract void parseFooter(byte[] footerBytes)
      throws DescriptorParseException;

  protected void parseDirectorySignature(byte[] directorySignatureBytes)
      throws DescriptorParseException {
    if (this.directorySignatures == null) {
      this.directorySignatures = new TreeMap<String, String>();
    }
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(directorySignatureBytes)));
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("directory-signature ")) {
          String[] parts = line.split(" ", -1);
          if (parts.length != 3) {
            throw new DescriptorParseException("Illegal line '" + line
                + "'.");
          }
          String identity = ParseHelper.parseTwentyByteHexString(line,
              parts[1]);
          String signingKeyDigest = ParseHelper.parseTwentyByteHexString(
              line, parts[2]);
          this.directorySignatures.put(identity, signingKeyDigest);
          break;
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  private String firstKeyword;
  protected void rememberFirstKeyword(byte[] headerBytes) {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(headerBytes)));
      this.firstKeyword = br.readLine().split(" ", -1)[0];
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  protected void checkFirstKeyword(String keyword)
      throws DescriptorParseException {
    if (this.firstKeyword == null ||
        !this.firstKeyword.equals(keyword)) {
      throw new DescriptorParseException("Keyword '" + keyword + "' must "
          + "be contained in the first line.");
    }
  }

  /* Count parsed keywords in header and footer for consistency checks by
   * subclasses. */
  private Map<String, Integer> parsedKeywords =
      new HashMap<String, Integer>();
  protected void countKeywords(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(rawDescriptorBytes)));
      String line;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("-----BEGIN")) {
          skipCrypto = true;
        } else if (line.startsWith("-----END")) {
          skipCrypto = false;
        } else if (!skipCrypto) {
          String keyword = line.split(" ", -1)[0];
          if (keyword.equals("")) {
            throw new DescriptorParseException("Illegal keyword in line '"
                + line + "'.");
          }
          if (parsedKeywords.containsKey(keyword)) {
            parsedKeywords.put(keyword, parsedKeywords.get(keyword) + 1);
          } else {
            parsedKeywords.put(keyword, 1);
          }
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    }
  }

  protected void checkExactlyOnceKeywords(Set<String> keywords)
      throws DescriptorParseException {
    for (String keyword : keywords) {
      int contained = 0;
      if (this.parsedKeywords.containsKey(keyword)) {
        contained = this.parsedKeywords.get(keyword);
      }
      if (contained != 1) {
        throw new DescriptorParseException("Keyword '" + keyword + "' is "
            + "contained " + contained + " times, but must be contained "
            + "exactly once.");
      }
    }
  }

  protected void checkAtLeastOnceKeywords(Set<String> keywords)
      throws DescriptorParseException {
    for (String keyword : keywords) {
      if (!this.parsedKeywords.containsKey(keyword)) {
        throw new DescriptorParseException("Keyword '" + keyword + "' is "
            + "contained 0 times, but must be contained at least once.");
      }
    }
  }

  protected void checkAtMostOnceKeywords(Set<String> keywords)
      throws DescriptorParseException {
    for (String keyword : keywords) {
      if (this.parsedKeywords.containsKey(keyword) &&
          this.parsedKeywords.get(keyword) > 1) {
        throw new DescriptorParseException("Keyword '" + keyword + "' is "
            + "contained " + this.parsedKeywords.get(keyword) + " times, "
            + "but must be contained at most once.");
      }
    }
  }

  private SortedMap<String, DirSourceEntry> dirSourceEntries =
      new TreeMap<String, DirSourceEntry>();
  public SortedMap<String, DirSourceEntry> getDirSourceEntries() {
    return new TreeMap<String, DirSourceEntry>(this.dirSourceEntries);
  }

  private SortedMap<String, NetworkStatusEntry> statusEntries =
      new TreeMap<String, NetworkStatusEntry>();
  public SortedMap<String, NetworkStatusEntry> getStatusEntries() {
    return new TreeMap<String, NetworkStatusEntry>(this.statusEntries);
  }
  public boolean containsStatusEntry(String fingerprint) {
    return this.statusEntries.containsKey(fingerprint);
  }
  public NetworkStatusEntry getStatusEntry(String fingerprint) {
    return this.statusEntries.get(fingerprint);
  }

  private SortedMap<String, String> directorySignatures;
  public SortedMap<String, String> getDirectorySignatures() {
    return this.directorySignatures == null ? null :
        new TreeMap<String, String>(this.directorySignatures);
  }
}

