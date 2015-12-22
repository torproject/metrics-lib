/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.RelayDirectory;
import org.torproject.descriptor.RouterStatusEntry;
import org.torproject.descriptor.ServerDescriptor;

/* TODO Write unit tests. */

public class RelayDirectoryImpl extends DescriptorImpl
    implements RelayDirectory {

  protected static List<RelayDirectory> parseDirectories(
      byte[] directoriesBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<RelayDirectory> parsedDirectories = new ArrayList<>();
    List<byte[]> splitDirectoriesBytes =
        DescriptorImpl.splitRawDescriptorBytes(directoriesBytes,
        "signed-directory\n");
    for (byte[] directoryBytes : splitDirectoriesBytes) {
      RelayDirectory parsedDirectory =
          new RelayDirectoryImpl(directoryBytes,
          failUnrecognizedDescriptorLines);
      parsedDirectories.add(parsedDirectory);
    }
    return parsedDirectories;
  }

  protected RelayDirectoryImpl(byte[] directoryBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(directoryBytes, failUnrecognizedDescriptorLines, true);
    this.splitAndParseParts(rawDescriptorBytes);
    this.calculateDigest();
    Set<String> exactlyOnceKeywords = new HashSet<>(Arrays.asList((
        "signed-directory,recommended-software,"
        + "directory-signature").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<>(Arrays.asList(
        "dir-signing-key,running-routers,router-status".split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkFirstKeyword("signed-directory");
    this.clearParsedKeywords();
  }

  private void calculateDigest() throws DescriptorParseException {
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "signed-directory\n";
      String sigToken = "\ndirectory-signature ";
      if (!ascii.contains(sigToken)) {
        return;
      }
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      sig = ascii.indexOf("\n", sig) + 1;
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, sig - start);
        this.directoryDigest = DatatypeConverter.printHexBinary(
            MessageDigest.getInstance("SHA-1").digest(forDigest)).
            toLowerCase();
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    } catch (NoSuchAlgorithmException e) {
      /* Handle below. */
    }
    if (this.directoryDigest == null) {
      throw new DescriptorParseException("Could not calculate v1 "
          + "directory digest.");
    }
  }

  private void splitAndParseParts(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    if (this.rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    String descriptorString = new String(rawDescriptorBytes);
    int startIndex = 0;
    int firstRouterIndex = this.findFirstIndexOfKeyword(descriptorString,
        "router");
    int directorySignatureIndex = this.findFirstIndexOfKeyword(
        descriptorString, "directory-signature");
    int endIndex = descriptorString.length();
    if (directorySignatureIndex < 0) {
      directorySignatureIndex = endIndex;
    }
    if (firstRouterIndex < 0) {
      firstRouterIndex = directorySignatureIndex;
    }
    if (firstRouterIndex > startIndex) {
      this.parseHeaderBytes(descriptorString, startIndex,
          firstRouterIndex);
    }
    if (directorySignatureIndex > firstRouterIndex) {
      this.parseServerDescriptorBytes(descriptorString, firstRouterIndex,
          directorySignatureIndex);
    }
    if (endIndex > directorySignatureIndex) {
      this.parseDirectorySignatureBytes(descriptorString,
          directorySignatureIndex, endIndex);
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

  private void parseServerDescriptorBytes(String descriptorString,
      int start, int end) throws DescriptorParseException {
    List<byte[]> splitServerDescriptorBytes =
        this.splitByKeyword(descriptorString, "router", start, end);
    for (byte[] statusEntryBytes : splitServerDescriptorBytes) {
      this.parseServerDescriptor(statusEntryBytes);
    }
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
    List<byte[]> splitParts = new ArrayList<>();
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
      int toNoNewline = to;
      while (toNoNewline > from &&
          descriptorString.charAt(toNoNewline - 1) == '\n') {
        toNoNewline--;
      }
      byte[] part = new byte[toNoNewline - from];
      System.arraycopy(this.rawDescriptorBytes, from, part, 0,
          toNoNewline - from);
      from = to;
      splitParts.add(part);
    }
    return splitParts;
  }

  private void parseHeader(byte[] headerBytes)
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(headerBytes)).useDelimiter("\n");
    String publishedLine = null, nextCrypto = "",
        runningRoutersLine = null, routerStatusLine = null;
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      if (line.isEmpty() || line.startsWith("@")) {
        continue;
      }
      String lineNoOpt = line.startsWith("opt ") ?
          line.substring("opt ".length()) : line;
      String[] partsNoOpt = lineNoOpt.split("[ \t]+");
      String keyword = partsNoOpt[0];
      switch (keyword) {
      case "signed-directory":
        this.parseSignedDirectoryLine(line, lineNoOpt, partsNoOpt);
        break;
      case "published":
        if (publishedLine != null) {
          throw new DescriptorParseException("Keyword 'published' is "
              + "contained more than once, but must be contained exactly "
              + "once.");
        } else {
          publishedLine = line;
        }
        break;
      case "dir-signing-key":
        this.parseDirSigningKeyLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "dir-signing-key";
        break;
      case "recommended-software":
        this.parseRecommendedSoftwareLine(line, lineNoOpt, partsNoOpt);
        break;
      case "running-routers":
        runningRoutersLine = line;
        break;
      case "router-status":
        routerStatusLine = line;
        break;
      default:
        if (line.startsWith("-----BEGIN")) {
          crypto = new StringBuilder();
          crypto.append(line + "\n");
        } else if (line.startsWith("-----END")) {
          crypto.append(line + "\n");
          String cryptoString = crypto.toString();
          crypto = null;
          if (nextCrypto.equals("dir-signing-key") &&
              this.dirSigningKey == null) {
            this.dirSigningKey = cryptoString;
          } else {
            throw new DescriptorParseException("Unrecognized crypto "
                + "block in v1 directory.");
          }
          nextCrypto = "";
        } else if (crypto != null) {
          crypto.append(line + "\n");
        } else {
          if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized line '"
                + line + "' in v1 directory.");
          } else {
            if (this.unrecognizedLines == null) {
              this.unrecognizedLines = new ArrayList<>();
            }
            this.unrecognizedLines.add(line);
          }
        }
      }
    }
    if (publishedLine == null) {
      throw new DescriptorParseException("Keyword 'published' is "
          + "contained 0 times, but must be contained exactly once.");
    } else {
      String publishedLineNoOpt = publishedLine.startsWith("opt ") ?
          publishedLine.substring("opt ".length()) : publishedLine;
      String[] publishedPartsNoOpt = publishedLineNoOpt.split("[ \t]+");
      this.parsePublishedLine(publishedLine, publishedLineNoOpt,
          publishedPartsNoOpt);
    }
    if (routerStatusLine != null) {
      String routerStatusLineNoOpt = routerStatusLine.startsWith("opt ") ?
          routerStatusLine.substring("opt ".length()) : routerStatusLine;
      String[] routerStatusPartsNoOpt =
          routerStatusLineNoOpt.split("[ \t]+");
      this.parseRouterStatusLine(routerStatusLine, routerStatusLineNoOpt,
          routerStatusPartsNoOpt);
    } else if (runningRoutersLine != null) {
      String runningRoutersLineNoOpt =
          runningRoutersLine.startsWith("opt ") ?
          runningRoutersLine.substring("opt ".length()) :
          runningRoutersLine;
      String[] runningRoutersPartsNoOpt =
          runningRoutersLineNoOpt.split("[ \t]+");
      this.parseRunningRoutersLine(runningRoutersLine,
          runningRoutersLineNoOpt, runningRoutersPartsNoOpt);
    } else {
      throw new DescriptorParseException("Either running-routers or "
          + "router-status line must be given.");
    }
  }

  protected void parseServerDescriptor(byte[] serverDescriptorBytes) {
    try {
      ServerDescriptorImpl serverDescriptor =
          new RelayServerDescriptorImpl(serverDescriptorBytes,
          this.failUnrecognizedDescriptorLines);
      this.serverDescriptors.add(serverDescriptor);
    } catch (DescriptorParseException e) {
      this.serverDescriptorParseExceptions.add(e);
    }
  }

  private void parseDirectorySignature(byte[] directorySignatureBytes)
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(directorySignatureBytes)).
        useDelimiter("\n");
    String nextCrypto = "";
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      String lineNoOpt = line.startsWith("opt ") ?
          line.substring("opt ".length()) : line;
      String[] partsNoOpt = lineNoOpt.split("[ \t]+");
      String keyword = partsNoOpt[0];
      if (keyword.equals("directory-signature")) {
        this.parseDirectorySignatureLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "directory-signature";
      } else if (line.startsWith("-----BEGIN")) {
        crypto = new StringBuilder();
        crypto.append(line + "\n");
      } else if (line.startsWith("-----END")) {
        crypto.append(line + "\n");
        String cryptoString = crypto.toString();
        crypto = null;
        if (nextCrypto.equals("directory-signature")) {
          this.directorySignature = cryptoString;
        } else {
          throw new DescriptorParseException("Unrecognized crypto "
              + "block in v2 network status.");
        }
        nextCrypto = "";
      } else if (crypto != null) {
        crypto.append(line + "\n");
      } else if (this.failUnrecognizedDescriptorLines) {
        throw new DescriptorParseException("Unrecognized line '" + line
            + "' in v2 network status.");
      } else {
        if (this.unrecognizedLines == null) {
          this.unrecognizedLines = new ArrayList<>();
        }
        this.unrecognizedLines.add(line);
      }
    }
  }

  private void parseSignedDirectoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("signed-directory")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parsePublishedLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line,
        partsNoOpt, 1, 2);
  }

  private void parseDirSigningKeyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length > 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    } else if (partsNoOpt.length == 2) {
      /* Early directories didn't have a crypto object following the
       * "dir-signing-key" line, but had the key base64-encoded in the
       * same line. */
      StringBuilder sb = new StringBuilder();
      sb.append("-----BEGIN RSA PUBLIC KEY-----\n");
      String keyString = partsNoOpt[1];
      while (keyString.length() > 64) {
        sb.append(keyString.substring(0, 64) + "\n");
        keyString = keyString.substring(64);
      }
      if (keyString.length() > 0) {
        sb.append(keyString + "\n");
      }
      sb.append("-----END RSA PUBLIC KEY-----\n");
      this.dirSigningKey = sb.toString();
    }
  }

  private void parseRecommendedSoftwareLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    List<String> result = new ArrayList<>();
    if (partsNoOpt.length > 2) {
      throw new DescriptorParseException("Illegal versions line '" + line
          + "'.");
    } else if (partsNoOpt.length == 2) {
      String[] versions = partsNoOpt[1].split(",", -1);
      for (int i = 0; i < versions.length; i++) {
        String version = versions[i];
        if (version.length() < 1) {
          throw new DescriptorParseException("Illegal versions line '"
              + line + "'.");
        }
        result.add(version);
      }
    }
    this.recommendedSoftware = result;
  }

  private void parseRunningRoutersLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    for (int i = 1; i < partsNoOpt.length; i++) {
      String part = partsNoOpt[i];
      String debugLine = "running-routers [...] " + part + " [...]";
      boolean isLive = true;
      if (part.startsWith("!")) {
        isLive = false;
        part = part.substring(1);
      }
      boolean isVerified;
      String fingerprint = null, nickname = null;
      if (part.startsWith("$")) {
        isVerified = false;
        fingerprint = ParseHelper.parseTwentyByteHexString(debugLine,
            part.substring(1));
      } else {
        isVerified = true;
        nickname = ParseHelper.parseNickname(debugLine, part);
      }
      this.statusEntries.add(new RouterStatusEntryImpl(fingerprint,
          nickname, isLive, isVerified));
    }
  }

  private void parseRouterStatusLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    for (int i = 1; i < partsNoOpt.length; i++) {
      String part = partsNoOpt[i];
      String debugLine = "router-status [...] " + part + " [...]";
      RouterStatusEntry entry = null;
      if (part.contains("=")) {
        String[] partParts = part.split("=");
        if (partParts.length == 2) {
          boolean isVerified = true, isLive;
          String nickname;
          if (partParts[0].startsWith("!")) {
            isLive = false;
            nickname = ParseHelper.parseNickname(debugLine,
                partParts[0].substring(1));
          } else {
            isLive = true;
            nickname = ParseHelper.parseNickname(debugLine, partParts[0]);
          }
          String fingerprint = ParseHelper.parseTwentyByteHexString(
              debugLine, partParts[1].substring(1));
          entry = new RouterStatusEntryImpl(fingerprint, nickname, isLive,
              isVerified);
        }
      } else {
        boolean isVerified = false, isLive;
        String nickname = null, fingerprint;
        if (part.startsWith("!")) {
          isLive = false;
          fingerprint = ParseHelper.parseTwentyByteHexString(
              debugLine, part.substring(2));
        } else {
          isLive = true;
          fingerprint = ParseHelper.parseTwentyByteHexString(
              debugLine, part.substring(1));;
        }
        entry = new RouterStatusEntryImpl(fingerprint, nickname, isLive,
            isVerified);
      }
      if (entry == null) {
        throw new DescriptorParseException("Illegal router-status entry '"
            + part + "' in v1 directory.");
      }
      this.statusEntries.add(entry);
    }
  }

  private void parseDirectorySignatureLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.nickname = ParseHelper.parseNickname(line, partsNoOpt[1]);
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private String dirSigningKey;
  public String getDirSigningKey() {
    return this.dirSigningKey;
  }

  private List<String> recommendedSoftware;
  public List<String> getRecommendedSoftware() {
    return this.recommendedSoftware == null ? null :
        new ArrayList<>(this.recommendedSoftware);
  }

  private String directorySignature;
  public String getDirectorySignature() {
    return this.directorySignature;
  }

  private List<RouterStatusEntry> statusEntries = new ArrayList<>();
  public List<RouterStatusEntry> getRouterStatusEntries() {
    return new ArrayList<>(this.statusEntries);
  }

  private List<ServerDescriptor> serverDescriptors = new ArrayList<>();
  public List<ServerDescriptor> getServerDescriptors() {
    return new ArrayList<>(this.serverDescriptors);
  }

  private List<Exception> serverDescriptorParseExceptions =
      new ArrayList<>();
  public List<Exception> getServerDescriptorParseExceptions() {
    return new ArrayList<>(this.serverDescriptorParseExceptions);
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String directoryDigest;
  public String getDirectoryDigest() {
    return this.directoryDigest;
  }
}

