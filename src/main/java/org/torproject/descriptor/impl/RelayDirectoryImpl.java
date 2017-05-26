/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.RelayDirectory;
import org.torproject.descriptor.RouterStatusEntry;
import org.torproject.descriptor.ServerDescriptor;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

public class RelayDirectoryImpl extends DescriptorImpl
    implements RelayDirectory {

  protected static List<RelayDirectory> parseDirectories(
      byte[] directoriesBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<RelayDirectory> parsedDirectories = new ArrayList<>();
    List<byte[]> splitDirectoriesBytes =
        DescriptorImpl.splitRawDescriptorBytes(directoriesBytes,
        Key.SIGNED_DIRECTORY.keyword + NL);
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
    Set<Key> exactlyOnceKeys = EnumSet.of(
        Key.SIGNED_DIRECTORY, Key.RECOMMENDED_SOFTWARE,
        Key.DIRECTORY_SIGNATURE);
    this.checkExactlyOnceKeys(exactlyOnceKeys);
    Set<Key> atMostOnceKeys = EnumSet.of(
        Key.DIR_SIGNING_KEY, Key.RUNNING_ROUTERS, Key.ROUTER_STATUS);
    this.checkAtMostOnceKeys(atMostOnceKeys);
    this.checkFirstKey(Key.SIGNED_DIRECTORY);
    this.clearParsedKeys();
  }

  private void calculateDigest() throws DescriptorParseException {
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = Key.SIGNED_DIRECTORY.keyword + NL;
      String sigToken = NL + Key.DIRECTORY_SIGNATURE.keyword + SP;
      if (!ascii.contains(sigToken)) {
        return;
      }
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      sig = ascii.indexOf(NL, sig) + 1;
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, sig - start);
        this.directoryDigest = DatatypeConverter.printHexBinary(
            MessageDigest.getInstance("SHA-1").digest(forDigest))
            .toLowerCase();
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
        Key.ROUTER.keyword);
    int directorySignatureIndex = this.findFirstIndexOfKeyword(
        descriptorString, Key.DIRECTORY_SIGNATURE.keyword);
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
    } else if (descriptorString.contains(NL + keyword + SP)) {
      return descriptorString.indexOf(NL + keyword + SP) + 1;
    } else if (descriptorString.contains(NL + keyword + NL)) {
      return descriptorString.indexOf(NL + keyword + NL) + 1;
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
        this.splitByKeyword(descriptorString, Key.ROUTER.keyword, start, end);
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
      int to = descriptorString.indexOf(NL + keyword + SP, from);
      if (to < 0) {
        to = descriptorString.indexOf(NL + keyword + NL, from);
      }
      if (to < 0) {
        to = end;
      } else {
        to += 1;
      }
      int toNoNewline = to;
      while (toNoNewline > from
          && descriptorString.charAt(toNoNewline - 1) == '\n') {
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
    Scanner scanner = new Scanner(new String(headerBytes)).useDelimiter(NL);
    String publishedLine = null;
    Key nextCrypto = Key.EMPTY;
    String runningRoutersLine = null;
    String routerStatusLine = null;
    StringBuilder crypto = null;
    while (scanner.hasNext()) {
      String line = scanner.next();
      if (line.isEmpty() || line.startsWith("@")) {
        continue;
      }
      String lineNoOpt = line.startsWith(Key.OPT.keyword + SP)
          ? line.substring(Key.OPT.keyword.length() + 1) : line;
      String[] partsNoOpt = lineNoOpt.split("[ \t]+");
      Key key = Key.get(partsNoOpt[0]);
      switch (key) {
        case SIGNED_DIRECTORY:
          this.parseSignedDirectoryLine(line, lineNoOpt, partsNoOpt);
          break;
        case PUBLISHED:
          if (publishedLine != null) {
            throw new DescriptorParseException("Keyword 'published' is "
                + "contained more than once, but must be contained "
                + "exactly once.");
          } else {
            publishedLine = line;
          }
          break;
        case DIR_SIGNING_KEY:
          this.parseDirSigningKeyLine(line, lineNoOpt, partsNoOpt);
          nextCrypto = key;
          break;
        case RECOMMENDED_SOFTWARE:
          this.parseRecommendedSoftwareLine(line, lineNoOpt, partsNoOpt);
          break;
        case RUNNING_ROUTERS:
          runningRoutersLine = line;
          break;
        case ROUTER_STATUS:
          routerStatusLine = line;
          break;
        case CRYPTO_BEGIN:
          crypto = new StringBuilder();
          crypto.append(line).append(NL);
          break;
        case CRYPTO_END:
          crypto.append(line).append(NL);
          String cryptoString = crypto.toString();
          crypto = null;
          if (nextCrypto.equals(Key.DIR_SIGNING_KEY)
              && this.dirSigningKey == null) {
            this.dirSigningKey = cryptoString;
          } else {
            throw new DescriptorParseException("Unrecognized crypto "
                + "block in v1 directory.");
          }
          nextCrypto = Key.EMPTY;
          break;
        default:
          if (crypto != null) {
            crypto.append(line).append(NL);
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
      String publishedLineNoOpt = publishedLine.startsWith(Key.OPT.keyword + SP)
          ? publishedLine.substring(Key.OPT.keyword.length() + 1)
          : publishedLine;
      String[] publishedPartsNoOpt = publishedLineNoOpt.split("[ \t]+");
      this.parsePublishedLine(publishedLine, publishedLineNoOpt,
          publishedPartsNoOpt);
    }
    if (routerStatusLine != null) {
      String routerStatusLineNoOpt =
          routerStatusLine.startsWith(Key.OPT.keyword + SP)
          ? routerStatusLine.substring(Key.OPT.keyword.length() + 1)
          : routerStatusLine;
      String[] routerStatusPartsNoOpt =
          routerStatusLineNoOpt.split("[ \t]+");
      this.parseRouterStatusLine(routerStatusLine, routerStatusLineNoOpt,
          routerStatusPartsNoOpt);
    } else if (runningRoutersLine != null) {
      String runningRoutersLineNoOpt =
          runningRoutersLine.startsWith(Key.OPT.keyword + SP)
          ? runningRoutersLine.substring(Key.OPT.keyword.length() + 1)
          : runningRoutersLine;
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
    Scanner scanner = new Scanner(new String(directorySignatureBytes))
        .useDelimiter(NL);
    Key nextCrypto = Key.EMPTY;
    StringBuilder crypto = null;
    while (scanner.hasNext()) {
      String line = scanner.next();
      String lineNoOpt = line.startsWith(Key.OPT.keyword + SP)
          ? line.substring(Key.OPT.keyword.length() + 1) : line;
      String[] partsNoOpt = lineNoOpt.split("[ \t]+");
      Key key = Key.get(partsNoOpt[0]);
      switch (key) {
        case DIRECTORY_SIGNATURE:
          this.parseDirectorySignatureLine(line, lineNoOpt, partsNoOpt);
          nextCrypto = key;
          break;
        case CRYPTO_BEGIN:
          crypto = new StringBuilder();
          crypto.append(line).append(NL);
          break;
        case CRYPTO_END:
          crypto.append(line).append(NL);
          String cryptoString = crypto.toString();
          crypto = null;
          if (nextCrypto.equals(Key.DIRECTORY_SIGNATURE)) {
            this.directorySignature = cryptoString;
          } else {
            throw new DescriptorParseException("Unrecognized crypto "
                + "block in v2 network status.");
          }
          nextCrypto = Key.EMPTY;
          break;
        default:
          if (crypto != null) {
            crypto.append(line).append(NL);
          } else if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized line '"
                + line + "' in v2 network status.");
          } else {
            if (this.unrecognizedLines == null) {
              this.unrecognizedLines = new ArrayList<>();
            }
            this.unrecognizedLines.add(line);
          }
      }
    }
  }

  private void parseSignedDirectoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals(Key.SIGNED_DIRECTORY.keyword)) {
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
        sb.append(keyString.substring(0, 64)).append(NL);
        keyString = keyString.substring(64);
      }
      if (keyString.length() > 0) {
        sb.append(keyString).append(NL);
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
      String fingerprint = null;
      String nickname = null;
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
          boolean isVerified = true;
          boolean isLive;
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
        boolean isVerified = false;
        boolean isLive;
        String nickname = null;
        String fingerprint;
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

  @Override
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private String dirSigningKey;

  @Override
  public String getDirSigningKey() {
    return this.dirSigningKey;
  }

  private List<String> recommendedSoftware;

  @Override
  public List<String> getRecommendedSoftware() {
    return this.recommendedSoftware == null ? null
        : new ArrayList<>(this.recommendedSoftware);
  }

  private String directorySignature;

  @Override
  public String getDirectorySignature() {
    return this.directorySignature;
  }

  private List<RouterStatusEntry> statusEntries = new ArrayList<>();

  @Override
  public List<RouterStatusEntry> getRouterStatusEntries() {
    return new ArrayList<>(this.statusEntries);
  }

  private List<ServerDescriptor> serverDescriptors = new ArrayList<>();

  @Override
  public List<ServerDescriptor> getServerDescriptors() {
    return new ArrayList<>(this.serverDescriptors);
  }

  private List<Exception> serverDescriptorParseExceptions =
      new ArrayList<>();

  @Override
  public List<Exception> getServerDescriptorParseExceptions() {
    return new ArrayList<>(this.serverDescriptorParseExceptions);
  }

  private String nickname;

  @Override
  public String getNickname() {
    return this.nickname;
  }

  private String directoryDigest;

  @Override
  public String getDirectoryDigest() {
    return this.getDigestSha1Hex();
  }

  @Override
  public String getDigestSha1Hex() {
    return this.directoryDigest;
  }
}

