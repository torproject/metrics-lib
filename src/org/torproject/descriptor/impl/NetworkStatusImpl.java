/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.SortedMap;
import java.util.TreeMap;

import org.torproject.descriptor.DirSourceEntry;
import org.torproject.descriptor.DirectorySignature;
import org.torproject.descriptor.NetworkStatusEntry;

/* Parse the common parts of v3 consensuses, v3 votes, v3 microdesc
 * consensuses, v2 statuses, and sanitized bridge network statuses and
 * delegate the specific parts to the subclasses. */
public abstract class NetworkStatusImpl extends DescriptorImpl {

  protected NetworkStatusImpl(byte[] rawDescriptorBytes,
      boolean failUnrecognizedDescriptorLines,
      boolean containsDirSourceEntries, boolean blankLinesAllowed)
      throws DescriptorParseException {
    super(rawDescriptorBytes, failUnrecognizedDescriptorLines,
        blankLinesAllowed);
    this.splitAndParseParts(this.rawDescriptorBytes,
        containsDirSourceEntries);
  }

  private void splitAndParseParts(byte[] rawDescriptorBytes,
      boolean containsDirSourceEntries) throws DescriptorParseException {
    if (this.rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    String descriptorString = new String(rawDescriptorBytes);
    int startIndex = 0;
    int firstDirSourceIndex = !containsDirSourceEntries ? -1 :
        this.findFirstIndexOfKeyword(descriptorString, "dir-source");
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
    DirSourceEntryImpl dirSourceEntry = new DirSourceEntryImpl(
        dirSourceBytes, this.failUnrecognizedDescriptorLines);
    this.dirSourceEntries.put(dirSourceEntry.getIdentity(),
        dirSourceEntry);
    List<String> unrecognizedDirSourceLines = dirSourceEntry.
        getAndClearUnrecognizedLines();
    if (unrecognizedDirSourceLines != null) {
      if (this.unrecognizedLines == null) {
        this.unrecognizedLines = new ArrayList<String>();
      }
      this.unrecognizedLines.addAll(unrecognizedDirSourceLines);
    }
  }

  protected String[] parseClientOrServerVersions(String line,
      String[] parts) throws DescriptorParseException {
    String[] result = null;
    if (parts.length > 2) {
      throw new DescriptorParseException("Illegal versions line '" + line
          + "'.");
    } else if (parts.length == 2) {
      result = parts[1].split(",", -1);
      for (String version : result) {
        if (version.length() < 1) {
          throw new DescriptorParseException("Illegal versions line '"
              + line + "'.");
        }
      }
    } else if (parts.length == 1) {
      result = new String[0];
    }
    return result;
  }

  protected void parseStatusEntry(byte[] statusEntryBytes)
      throws DescriptorParseException {
    NetworkStatusEntryImpl statusEntry = new NetworkStatusEntryImpl(
        statusEntryBytes, false, this.failUnrecognizedDescriptorLines);
    this.statusEntries.put(statusEntry.getFingerprint(), statusEntry);
    List<String> unrecognizedStatusEntryLines = statusEntry.
        getAndClearUnrecognizedLines();
    if (unrecognizedStatusEntryLines != null) {
      if (this.unrecognizedLines == null) {
        this.unrecognizedLines = new ArrayList<String>();
      }
      this.unrecognizedLines.addAll(unrecognizedStatusEntryLines);
    }
  }

  protected abstract void parseFooter(byte[] footerBytes)
      throws DescriptorParseException;

  protected void parseDirectorySignature(byte[] directorySignatureBytes)
      throws DescriptorParseException {
    if (this.directorySignatures == null) {
      this.directorySignatures = new TreeMap<String,
          DirectorySignature>();
    }
    DirectorySignatureImpl signature = new DirectorySignatureImpl(
        directorySignatureBytes, failUnrecognizedDescriptorLines);
    this.directorySignatures.put(signature.getIdentity(), signature);
    List<String> unrecognizedStatusEntryLines = signature.
        getAndClearUnrecognizedLines();
    if (unrecognizedStatusEntryLines != null) {
      if (this.unrecognizedLines == null) {
        this.unrecognizedLines = new ArrayList<String>();
      }
      this.unrecognizedLines.addAll(unrecognizedStatusEntryLines);
    }
  }

  protected SortedMap<String, DirSourceEntry> dirSourceEntries =
      new TreeMap<String, DirSourceEntry>();
  public SortedMap<String, DirSourceEntry> getDirSourceEntries() {
    return new TreeMap<String, DirSourceEntry>(this.dirSourceEntries);
  }

  protected SortedMap<String, NetworkStatusEntry> statusEntries =
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

  protected SortedMap<String, DirectorySignature> directorySignatures;
  public SortedMap<String, DirectorySignature> getDirectorySignatures() {
    return this.directorySignatures == null ? null :
        new TreeMap<String, DirectorySignature>(this.directorySignatures);
  }
}

