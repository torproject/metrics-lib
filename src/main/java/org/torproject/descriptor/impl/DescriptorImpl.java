/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import javax.xml.bind.DatatypeConverter;

public abstract class DescriptorImpl implements Descriptor {

  public static final String NL = "\n";

  public static final String SP = " ";

  protected static List<Descriptor> parseDescriptors(
      byte[] rawDescriptorBytes, String fileName,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<Descriptor> parsedDescriptors = new ArrayList<>();
    if (rawDescriptorBytes == null) {
      return parsedDescriptors;
    }
    byte[] first100Chars = new byte[Math.min(100,
        rawDescriptorBytes.length)];
    System.arraycopy(rawDescriptorBytes, 0, first100Chars, 0,
        first100Chars.length);
    String firstLines = new String(first100Chars);
    if (firstLines.startsWith("@type network-status-consensus-3 1.")
        || firstLines.startsWith(
            "@type network-status-microdesc-consensus-3 1.")
        || ((firstLines.startsWith(
            Key.NETWORK_STATUS_VERSION.keyword + SP + "3")
        || firstLines.contains(
            NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "3"))
        && firstLines.contains(
            NL + Key.VOTE_STATUS.keyword + SP + "consensus" + NL))) {
      parsedDescriptors.addAll(RelayNetworkStatusConsensusImpl
          .parseConsensuses(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type network-status-vote-3 1.")
        || ((firstLines.startsWith(
            Key.NETWORK_STATUS_VERSION.keyword + SP + "3" + NL)
        || firstLines.contains(
            NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "3" + NL))
        && firstLines.contains(
            NL + Key.VOTE_STATUS.keyword + SP + "vote" + NL))) {
      parsedDescriptors.addAll(RelayNetworkStatusVoteImpl
          .parseVotes(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type bridge-network-status 1.")
        || firstLines.startsWith(Key.R.keyword + SP)) {
      parsedDescriptors.add(new BridgeNetworkStatusImpl(
          rawDescriptorBytes, fileName, failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type bridge-server-descriptor 1.")) {
      parsedDescriptors.addAll(BridgeServerDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type server-descriptor 1.")
        || firstLines.startsWith(Key.ROUTER.keyword + SP)
        || firstLines.contains(NL + Key.ROUTER.keyword + SP)) {
      parsedDescriptors.addAll(RelayServerDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type bridge-extra-info 1.")) {
      parsedDescriptors.addAll(BridgeExtraInfoDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type extra-info 1.")
        || firstLines.startsWith(Key.EXTRA_INFO.keyword + SP)
        || firstLines.contains(NL + Key.EXTRA_INFO.keyword + SP)) {
      parsedDescriptors.addAll(RelayExtraInfoDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type microdescriptor 1.")
        || firstLines.startsWith(Key.ONION_KEY.keyword + NL)
        || firstLines.contains(NL + Key.ONION_KEY.keyword + NL)) {
      parsedDescriptors.addAll(MicrodescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type bridge-pool-assignment 1.")
        || firstLines.startsWith(Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP)
        || firstLines.contains(NL + Key.BRIDGE_POOL_ASSIGNMENT.keyword + SP)) {
      parsedDescriptors.addAll(BridgePoolAssignmentImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type dir-key-certificate-3 1.")
        || firstLines.startsWith(Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP)
        || firstLines.contains(
            NL + Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP)) {
      parsedDescriptors.addAll(DirectoryKeyCertificateImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type tordnsel 1.")
        || firstLines.startsWith("ExitNode" + SP)
        || firstLines.contains(NL + "ExitNode" + SP)) {
      parsedDescriptors.add(new ExitListImpl(rawDescriptorBytes, fileName,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type network-status-2 1.")
        || firstLines.startsWith(
            Key.NETWORK_STATUS_VERSION.keyword + SP + "2" + NL)
        || firstLines.contains(
            NL + Key.NETWORK_STATUS_VERSION.keyword + SP + "2" + NL)) {
      parsedDescriptors.add(new RelayNetworkStatusImpl(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type directory 1.")
        || firstLines.startsWith(Key.SIGNED_DIRECTORY.keyword + NL)
        || firstLines.contains(NL + Key.SIGNED_DIRECTORY.keyword + NL)) {
      parsedDescriptors.add(new RelayDirectoryImpl(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type torperf 1.")) {
      parsedDescriptors.addAll(TorperfResultImpl.parseTorperfResults(
          rawDescriptorBytes, failUnrecognizedDescriptorLines));
    } else {
      throw new DescriptorParseException("Could not detect descriptor "
          + "type in descriptor starting with '" + firstLines + "'.");
    }
    return parsedDescriptors;
  }

  protected static List<byte[]> splitRawDescriptorBytes(
      byte[] rawDescriptorBytes, String startToken) {
    List<byte[]> rawDescriptors = new ArrayList<>();
    String splitToken = NL + startToken;
    String ascii;
    try {
      ascii = new String(rawDescriptorBytes, "US-ASCII");
    } catch (UnsupportedEncodingException e) {
      return rawDescriptors;
    }
    int endAllDescriptors = rawDescriptorBytes.length;
    int startAnnotations = 0;
    boolean containsAnnotations = ascii.startsWith("@")
        || ascii.contains(NL + "@");
    while (startAnnotations < endAllDescriptors) {
      int startDescriptor;
      if (ascii.indexOf(startToken, startAnnotations) == 0) {
        startDescriptor = startAnnotations;
      } else {
        startDescriptor = ascii.indexOf(splitToken, startAnnotations - 1);
        if (startDescriptor < 0) {
          break;
        } else {
          startDescriptor += 1;
        }
      }
      int endDescriptor = -1;
      if (containsAnnotations) {
        endDescriptor = ascii.indexOf(NL + "@", startDescriptor);
      }
      if (endDescriptor < 0) {
        endDescriptor = ascii.indexOf(splitToken, startDescriptor);
      }
      if (endDescriptor < 0) {
        endDescriptor = endAllDescriptors - 1;
      }
      endDescriptor += 1;
      byte[] rawDescriptor = new byte[endDescriptor - startAnnotations];
      System.arraycopy(rawDescriptorBytes, startAnnotations,
          rawDescriptor, 0, endDescriptor - startAnnotations);
      startAnnotations = endDescriptor;
      rawDescriptors.add(rawDescriptor);
    }
    return rawDescriptors;
  }

  protected byte[] rawDescriptorBytes;

  @Override
  public byte[] getRawDescriptorBytes() {
    return this.rawDescriptorBytes;
  }

  protected boolean failUnrecognizedDescriptorLines = false;

  protected List<String> unrecognizedLines;

  @Override
  public List<String> getUnrecognizedLines() {
    return this.unrecognizedLines == null ? new ArrayList<String>()
        : new ArrayList<>(this.unrecognizedLines);
  }

  protected DescriptorImpl(byte[] rawDescriptorBytes,
      boolean failUnrecognizedDescriptorLines, boolean blankLinesAllowed)
      throws DescriptorParseException {
    this.rawDescriptorBytes = rawDescriptorBytes;
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
    this.cutOffAnnotations(rawDescriptorBytes);
    this.countKeys(rawDescriptorBytes, blankLinesAllowed);
  }

  /* Parse annotation lines from the descriptor bytes. */
  private List<String> annotations = new ArrayList<>();

  private void cutOffAnnotations(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    String ascii = new String(rawDescriptorBytes);
    int start = 0;
    while ((start == 0 && ascii.startsWith("@"))
        || (start > 0 && ascii.indexOf(NL + "@", start - 1) >= 0)) {
      int end = ascii.indexOf(NL, start);
      if (end < 0) {
        throw new DescriptorParseException("Annotation line does not "
            + "contain a newline.");
      }
      this.annotations.add(ascii.substring(start, end));
      start = end + 1;
    }
    if (start > 0) {
      int length = rawDescriptorBytes.length;
      byte[] rawDescriptor = new byte[length - start];
      System.arraycopy(rawDescriptorBytes, start, rawDescriptor, 0,
          length - start);
      this.rawDescriptorBytes = rawDescriptor;
    }
  }

  @Override
  public List<String> getAnnotations() {
    return new ArrayList<>(this.annotations);
  }

  private Key firstKey = Key.EMPTY;

  private Key lastKey = Key.EMPTY;

  private Map<Key, Integer> parsedKeys = new EnumMap<>(Key.class);

  /* Count parsed keywords for consistency checks by subclasses. */
  private void countKeys(byte[] rawDescriptorBytes,
      boolean blankLinesAllowed) throws DescriptorParseException {
    if (rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    String descriptorString = new String(rawDescriptorBytes);
    if (!blankLinesAllowed && (descriptorString.startsWith(NL)
        || descriptorString.contains(NL + NL))) {
      throw new DescriptorParseException("Blank lines are not allowed.");
    }
    boolean skipCrypto = false;
    Scanner scanner = new Scanner(descriptorString).useDelimiter(NL);
    while (scanner.hasNext()) {
      String line = scanner.next();
      if (line.startsWith(Key.CRYPTO_BEGIN.keyword)) {
        skipCrypto = true;
      } else if (line.startsWith(Key.CRYPTO_END.keyword)) {
        skipCrypto = false;
      } else if (!line.isEmpty() && !line.startsWith("@")
          && !skipCrypto) {
        String lineNoOpt = line.startsWith(Key.OPT.keyword + SP)
            ? line.substring(Key.OPT.keyword.length() + 1) : line;
        String keyword = lineNoOpt.split(SP, -1)[0];
        if (keyword.equals("")) {
          throw new DescriptorParseException("Illegal keyword in line '"
              + line + "'.");
        }
        Key key = Key.get(keyword);
        if (Key.EMPTY == this.firstKey) {
          this.firstKey = key;
        }
        lastKey = key;
        if (parsedKeys.containsKey(key)) {
          parsedKeys.put(key, parsedKeys.get(key) + 1);
        } else {
          parsedKeys.put(key, 1);
        }
      }
    }
  }

  protected void checkFirstKey(Key key)
      throws DescriptorParseException {
    if (this.firstKey != key) {
      throw new DescriptorParseException("Keyword '" + key.keyword + "' must "
          + "be contained in the first line.");
    }
  }

  protected void checkLastKey(Key key)
      throws DescriptorParseException {
    if (this.lastKey != key) {
      throw new DescriptorParseException("Keyword '" + key.keyword + "' must "
          + "be contained in the last line.");
    }
  }

  protected void checkExactlyOnceKeys(Set<Key> keys)
      throws DescriptorParseException {
    for (Key key : keys) {
      int contained = 0;
      if (this.parsedKeys.containsKey(key)) {
        contained = this.parsedKeys.get(key);
      }
      if (contained != 1) {
        throw new DescriptorParseException("Keyword '" + key.keyword + "' is "
            + "contained " + contained + " times, but must be contained "
            + "exactly once.");
      }
    }
  }

  protected void checkAtLeastOnceKeys(Set<Key> keys)
      throws DescriptorParseException {
    for (Key key : keys) {
      if (!this.parsedKeys.containsKey(key)) {
        throw new DescriptorParseException("Keyword '" + key.keyword + "' is "
            + "contained 0 times, but must be contained at least once.");
      }
    }
  }

  protected void checkAtMostOnceKeys(Set<Key> keys)
      throws DescriptorParseException {
    for (Key key : keys) {
      if (this.parsedKeys.containsKey(key)
          && this.parsedKeys.get(key) > 1) {
        throw new DescriptorParseException("Keyword '" + key.keyword + "' is "
            + "contained " + this.parsedKeys.get(key) + " times, "
            + "but must be contained at most once.");
      }
    }
  }

  protected void checkKeysDependOn(Set<Key> dependentKeys,
      Key dependingKey) throws DescriptorParseException {
    for (Key dependentKey : dependentKeys) {
      if (this.parsedKeys.containsKey(dependentKey)
          && !this.parsedKeys.containsKey(dependingKey)) {
        throw new DescriptorParseException("Keyword '" + dependentKey.keyword
            + "' is contained, but keyword '" + dependingKey.keyword + "' is "
            + "not.");
      }
    }
  }

  protected int getKeyCount(Key key) {
    if (!this.parsedKeys.containsKey(key)) {
      return 0;
    } else {
      return this.parsedKeys.get(key);
    }
  }

  protected void clearParsedKeys() {
    this.parsedKeys = null;
  }

  private String digestSha1Hex;

  protected void setDigestSha1Hex(String digestSha1Hex) {
    this.digestSha1Hex = digestSha1Hex;
  }

  protected void calculateDigestSha1Hex(String startToken, String endToken)
      throws DescriptorParseException {
    if (null == this.digestSha1Hex) {
      String ascii = new String(this.rawDescriptorBytes,
          StandardCharsets.US_ASCII);
      int start = ascii.indexOf(startToken);
      int end = -1;
      if (null == endToken) {
        end = ascii.length();
      } else if (ascii.contains(endToken)) {
        end = ascii.indexOf(endToken) + endToken.length();
      }
      if (start >= 0 && end >= 0 && end > start) {
        byte[] forDigest = new byte[end - start];
        System.arraycopy(this.rawDescriptorBytes, start, forDigest, 0,
            end - start);
        try {
          this.digestSha1Hex = DatatypeConverter.printHexBinary(
              MessageDigest.getInstance("SHA-1").digest(forDigest))
              .toLowerCase();
        } catch (NoSuchAlgorithmException e) {
          /* Handle below. */
        }
      }
    }
    if (null == this.digestSha1Hex) {
      throw new DescriptorParseException("Could not calculate descriptor "
          + "digest.");
    }
  }

  public String getDigestSha1Hex() {
    return this.digestSha1Hex;
  }

  private String digestSha256Base64;

  protected void setDigestSha256Base64(String digestSha256Base64) {
    this.digestSha256Base64 = digestSha256Base64;
  }

  protected void calculateDigestSha256Base64(String startToken,
      String endToken) throws DescriptorParseException {
    if (null == this.digestSha256Base64) {
      String ascii = new String(this.rawDescriptorBytes,
          StandardCharsets.US_ASCII);
      int start = ascii.indexOf(startToken);
      int end = -1;
      if (null == endToken) {
        end = ascii.length();
      } else if (ascii.contains(endToken)) {
        end = ascii.indexOf(endToken) + endToken.length();
      }
      if (start >= 0 && end >= 0 && end > start) {
        byte[] forDigest = new byte[end - start];
        System.arraycopy(this.rawDescriptorBytes, start, forDigest, 0,
            end - start);
        try {
          this.digestSha256Base64 = DatatypeConverter.printBase64Binary(
              MessageDigest.getInstance("SHA-256").digest(forDigest))
              .replaceAll("=", "");
        } catch (NoSuchAlgorithmException e) {
          /* Handle below. */
        }
      }
    }
    if (null == this.digestSha256Base64) {
      throw new DescriptorParseException("Could not calculate descriptor "
          + "digest.");
    }
  }

  protected void calculateDigestSha256Base64(String startToken)
      throws DescriptorParseException {
    this.calculateDigestSha256Base64(startToken, null);
  }

  public String getDigestSha256Base64() {
    return this.digestSha256Base64;
  }
}

