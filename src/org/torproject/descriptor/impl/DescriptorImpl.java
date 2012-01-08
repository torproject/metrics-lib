/* Copyright 2012 The Tor Project
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
import org.torproject.descriptor.Descriptor;

public abstract class DescriptorImpl implements Descriptor {

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

  protected byte[] rawDescriptorBytes;
  public byte[] getRawDescriptorBytes() {
    return this.rawDescriptorBytes;
  }

  protected DescriptorImpl(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    this.rawDescriptorBytes = rawDescriptorBytes;
    this.countKeywords(rawDescriptorBytes);
  }

  /* Count parsed keywords for consistency checks by subclasses. */
  private String firstKeyword, lastKeyword;
  private Map<String, Integer> parsedKeywords =
      new HashMap<String, Integer>();
  private void countKeywords(byte[] rawDescriptorBytes)
      throws DescriptorParseException {
    if (rawDescriptorBytes.length == 0) {
      throw new DescriptorParseException("Descriptor is empty.");
    }
    String descriptorString = new String(rawDescriptorBytes);
    if (descriptorString.startsWith("\n") ||
        descriptorString.contains("\n\n")) {
      throw new DescriptorParseException("Empty lines are not allowed.");
    }
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          descriptorString));
      String line;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("-----BEGIN")) {
          skipCrypto = true;
        } else if (line.startsWith("-----END")) {
          skipCrypto = false;
        } else if (!line.startsWith("@") && !skipCrypto) {
          String lineNoOpt = line.startsWith("opt ") ?
              line.substring("opt ".length()) : line;
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

  protected void checkLastKeyword(String keyword)
      throws DescriptorParseException {
    if (this.lastKeyword == null ||
        !this.lastKeyword.equals(keyword)) {
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
      if (this.parsedKeywords.containsKey(keyword) &&
          this.parsedKeywords.get(keyword) > 1) {
        throw new DescriptorParseException("Keyword '" + keyword + "' is "
            + "contained " + this.parsedKeywords.get(keyword) + " times, "
            + "but must be contained at most once.");
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
}

