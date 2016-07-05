/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

public abstract class DescriptorImpl implements Descriptor {

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
        || firstLines.startsWith("@type network-status-microdesc-"
            + "consensus-3 1.")
        || ((firstLines.startsWith("network-status-version 3")
        || firstLines.contains("\nnetwork-status-version 3"))
        && firstLines.contains("\nvote-status consensus\n"))) {
      parsedDescriptors.addAll(RelayNetworkStatusConsensusImpl
          .parseConsensuses(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type network-status-vote-3 1.")
        || ((firstLines.startsWith("network-status-version 3\n")
        || firstLines.contains("\nnetwork-status-version 3\n"))
        && firstLines.contains("\nvote-status vote\n"))) {
      parsedDescriptors.addAll(RelayNetworkStatusVoteImpl
          .parseVotes(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type bridge-network-status 1.")
        || firstLines.startsWith("r ")) {
      parsedDescriptors.add(new BridgeNetworkStatusImpl(
          rawDescriptorBytes, fileName, failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith(
        "@type bridge-server-descriptor 1.")) {
      parsedDescriptors.addAll(BridgeServerDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type server-descriptor 1.")
        || firstLines.startsWith("router ")
        || firstLines.contains("\nrouter ")) {
      parsedDescriptors.addAll(RelayServerDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type bridge-extra-info 1.")) {
      parsedDescriptors.addAll(BridgeExtraInfoDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type extra-info 1.")
        || firstLines.startsWith("extra-info ")
        || firstLines.contains("\nextra-info ")) {
      parsedDescriptors.addAll(RelayExtraInfoDescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type microdescriptor 1.")
        || firstLines.startsWith("onion-key\n")
        || firstLines.contains("\nonion-key\n")) {
      parsedDescriptors.addAll(MicrodescriptorImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type bridge-pool-assignment 1.")
        || firstLines.startsWith("bridge-pool-assignment ")
        || firstLines.contains("\nbridge-pool-assignment ")) {
      parsedDescriptors.addAll(BridgePoolAssignmentImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type dir-key-certificate-3 1.")
        || firstLines.startsWith("dir-key-certificate-version ")
        || firstLines.contains("\ndir-key-certificate-version ")) {
      parsedDescriptors.addAll(DirectoryKeyCertificateImpl
          .parseDescriptors(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type tordnsel 1.")
        || firstLines.startsWith("ExitNode ")
        || firstLines.contains("\nExitNode ")) {
      parsedDescriptors.add(new ExitListImpl(rawDescriptorBytes, fileName,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type network-status-2 1.")
        || firstLines.startsWith("network-status-version 2\n")
        || firstLines.contains("\nnetwork-status-version 2\n")) {
      parsedDescriptors.add(new RelayNetworkStatusImpl(rawDescriptorBytes,
          failUnrecognizedDescriptorLines));
    } else if (firstLines.startsWith("@type directory 1.")
        || firstLines.startsWith("signed-directory\n")
        || firstLines.contains("\nsigned-directory\n")) {
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
    String splitToken = "\n" + startToken;
    String ascii;
    try {
      ascii = new String(rawDescriptorBytes, "US-ASCII");
    } catch (UnsupportedEncodingException e) {
      return rawDescriptors;
    }
    int endAllDescriptors = rawDescriptorBytes.length;
    int startAnnotations = 0;
    boolean containsAnnotations = ascii.startsWith("@")
        || ascii.contains("\n@");
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
        endDescriptor = ascii.indexOf("\n@", startDescriptor);
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
    this.countKeywords(rawDescriptorBytes, blankLinesAllowed);
  }

  /* Parse annotation lines from the descriptor bytes. */
  private List<String> annotations = new ArrayList<>();

  private void cutOffAnnotations(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    String ascii = new String(rawDescriptorBytes);
    int start = 0;
    while ((start == 0 && ascii.startsWith("@"))
        || (start > 0 && ascii.indexOf("\n@", start - 1) >= 0)) {
      int end = ascii.indexOf("\n", start);
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

  private String firstKeyword;

  private String lastKeyword;

  private Map<String, Integer> parsedKeywords = new HashMap<>();

  /* Count parsed keywords for consistency checks by subclasses. */
  private void countKeywords(byte[] rawDescriptorBytes,
      boolean blankLinesAllowed) throws DescriptorParseException {
    if (rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    String descriptorString = new String(rawDescriptorBytes);
    if (!blankLinesAllowed && (descriptorString.startsWith("\n")
        || descriptorString.contains("\n\n"))) {
      throw new DescriptorParseException("Blank lines are not allowed.");
    }
    boolean skipCrypto = false;
    Scanner s = new Scanner(descriptorString).useDelimiter("\n");
    while (s.hasNext()) {
      String line = s.next();
      if (line.startsWith("-----BEGIN")) {
        skipCrypto = true;
      } else if (line.startsWith("-----END")) {
        skipCrypto = false;
      } else if (!line.isEmpty() && !line.startsWith("@")
          && !skipCrypto) {
        String lineNoOpt = line.startsWith("opt ")
            ? line.substring("opt ".length()) : line;
        String keyword = lineNoOpt.split(" ", -1)[0];
        if (keyword.equals("")) {
          throw new DescriptorParseException("Illegal keyword in line '"
              + line + "'.");
        }
        if (this.firstKeyword == null) {
          this.firstKeyword = keyword;
        }
        lastKeyword = keyword;
        if (parsedKeywords.containsKey(keyword)) {
          parsedKeywords.put(keyword, parsedKeywords.get(keyword) + 1);
        } else {
          parsedKeywords.put(keyword, 1);
        }
      }
    }
  }

  protected void checkFirstKeyword(String keyword)
      throws DescriptorParseException {
    if (this.firstKeyword == null
        || !this.firstKeyword.equals(keyword)) {
      throw new DescriptorParseException("Keyword '" + keyword + "' must "
          + "be contained in the first line.");
    }
  }

  protected void checkLastKeyword(String keyword)
      throws DescriptorParseException {
    if (this.lastKeyword == null
        || !this.lastKeyword.equals(keyword)) {
      throw new DescriptorParseException("Keyword '" + keyword + "' must "
          + "be contained in the last line.");
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
      if (this.parsedKeywords.containsKey(keyword)
          && this.parsedKeywords.get(keyword) > 1) {
        throw new DescriptorParseException("Keyword '" + keyword + "' is "
            + "contained " + this.parsedKeywords.get(keyword) + " times, "
            + "but must be contained at most once.");
      }
    }
  }

  protected void checkKeywordsDependOn(Set<String> dependentKeywords,
      String dependingKeyword) throws DescriptorParseException {
    for (String dependentKeyword : dependentKeywords) {
      if (this.parsedKeywords.containsKey(dependentKeyword)
          && !this.parsedKeywords.containsKey(dependingKeyword)) {
        throw new DescriptorParseException("Keyword '" + dependentKeyword
            + "' is contained, but keyword '" + dependingKeyword + "' is "
            + "not.");
      }
    }
  }

  protected int getKeywordCount(String keyword) {
    if (!this.parsedKeywords.containsKey(keyword)) {
      return 0;
    } else {
      return this.parsedKeywords.get(keyword);
    }
  }

  protected void clearParsedKeywords() {
    this.parsedKeywords = null;
  }
}

