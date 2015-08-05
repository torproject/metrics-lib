/* Copyright 2014--2015 The Tor Project
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
import org.torproject.descriptor.Microdescriptor;

/* Contains a microdescriptor. */
public class MicrodescriptorImpl extends DescriptorImpl
    implements Microdescriptor {

  protected static List<Microdescriptor> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<Microdescriptor> parsedDescriptors =
        new ArrayList<Microdescriptor>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "onion-key\n");
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      Microdescriptor parsedDescriptor =
          new MicrodescriptorImpl(descriptorBytes,
          failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected MicrodescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseDescriptorBytes();
    this.calculateDigest();
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList(
        "onion-key".split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList((
        "ntor-onion-key,family,p,p6").split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkFirstKeyword("onion-key");
    this.clearParsedKeywords();
    return;
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.rawDescriptorBytes)).
        useDelimiter("\n");
    String nextCrypto = null;
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      if (line.startsWith("@")) {
        continue;
      }
      String[] parts = line.split("[ \t]+");
      String keyword = parts[0];
      if (keyword.equals("onion-key")) {
        this.parseOnionKeyLine(line, parts);
        nextCrypto = "onion-key";
      } else if (keyword.equals("ntor-onion-key")) {
        this.parseNtorOnionKeyLine(line, parts);
      } else if (keyword.equals("a")) {
        this.parseALine(line, parts);
      } else if (keyword.equals("family")) {
        this.parseFamilyLine(line, parts);
      } else if (keyword.equals("p")) {
        this.parsePLine(line, parts);
      } else if (keyword.equals("p6")) {
        this.parseP6Line(line, parts);
      } else if (line.startsWith("-----BEGIN")) {
        crypto = new StringBuilder();
        crypto.append(line + "\n");
      } else if (line.startsWith("-----END")) {
        crypto.append(line + "\n");
        String cryptoString = crypto.toString();
        crypto = null;
        if (nextCrypto.equals("onion-key")) {
          this.onionKey = cryptoString;
        } else {
          throw new DescriptorParseException("Unrecognized crypto "
              + "block in microdescriptor.");
        }
        nextCrypto = null;
      } else if (crypto != null) {
        crypto.append(line + "\n");
      } else {
        ParseHelper.parseKeyword(line, parts[0]);
        if (this.failUnrecognizedDescriptorLines) {
          throw new DescriptorParseException("Unrecognized line '"
              + line + "' in microdescriptor.");
        } else {
          if (this.unrecognizedLines == null) {
            this.unrecognizedLines = new ArrayList<String>();
          }
          this.unrecognizedLines.add(line);
        }
      }
    }
  }

  private void parseOnionKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("onion-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseNtorOnionKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.ntorOnionKey = parts[1].replaceAll("=", "");
  }

  private void parseALine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Wrong number of values in line "
          + "'" + line + "'.");
    }
    /* TODO Add more checks. */
    /* TODO Add tests. */
    this.orAddresses.add(parts[1]);
  }

  private void parseFamilyLine(String line, String[] parts)
      throws DescriptorParseException {
    String[] familyEntries = new String[parts.length - 1];
    for (int i = 1; i < parts.length; i++) {
      if (parts[i].startsWith("$")) {
        if (parts[i].contains("=") ^ parts[i].contains("~")) {
          String separator = parts[i].contains("=") ? "=" : "~";
          String fingerprint = ParseHelper.parseTwentyByteHexString(line,
              parts[i].substring(1, parts[i].indexOf(separator)));
          String nickname = ParseHelper.parseNickname(line,
              parts[i].substring(parts[i].indexOf(separator) + 1));
          familyEntries[i - 1] = "$" + fingerprint + separator + nickname;
        } else {
          familyEntries[i - 1] = "$"
              + ParseHelper.parseTwentyByteHexString(line,
              parts[i].substring(1));
        }
      } else {
        familyEntries[i - 1] = ParseHelper.parseNickname(line, parts[i]);
      }
    }
    this.familyEntries = familyEntries;
  }

  private void parsePLine(String line, String[] parts)
      throws DescriptorParseException {
    this.validatePOrP6Line(line, parts);
    this.defaultPolicy = parts[1];
    this.portList = parts[2];
  }

  private void parseP6Line(String line, String[] parts)
      throws DescriptorParseException {
    this.validatePOrP6Line(line, parts);
    this.ipv6DefaultPolicy = parts[1];
    this.ipv6PortList = parts[2];
  }

  private void validatePOrP6Line(String line, String[] parts)
      throws DescriptorParseException {
    boolean isValid = true;
    if (parts.length != 3) {
      isValid = false;
    } else if (!parts[1].equals("accept") && !parts[1].equals("reject")) {
      isValid = false;
    } else {
      String[] ports = parts[2].split(",", -1);
      for (int i = 0; i < ports.length; i++) {
        if (ports[i].length() < 1) {
          isValid = false;
          break;
        }
      }
    }
    if (!isValid) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void calculateDigest() throws DescriptorParseException {
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "onion-key\n";
      int start = ascii.indexOf(startToken);
      int end = ascii.length();
      if (start >= 0 && end > start) {
        byte[] forDigest = new byte[end - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, end - start);
        this.microdescriptorDigest = DatatypeConverter.printHexBinary(
            MessageDigest.getInstance("SHA-256").digest(forDigest));
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    } catch (NoSuchAlgorithmException e) {
      /* Handle below. */
    }
    if (this.microdescriptorDigest == null) {
      throw new DescriptorParseException("Could not calculate "
          + "microdescriptor digest.");
    }
  }

  private String microdescriptorDigest;
  public String getMicrodescriptorDigest() {
    return this.microdescriptorDigest;
  }

  private String onionKey;
  public String getOnionKey() {
    return this.onionKey;
  }

  private String ntorOnionKey;
  public String getNtorOnionKey() {
    return this.ntorOnionKey;
  }

  private List<String> orAddresses = new ArrayList<String>();
  public List<String> getOrAddresses() {
    return new ArrayList<String>(this.orAddresses);
  }

  private String[] familyEntries;
  public List<String> getFamilyEntries() {
    return this.familyEntries == null ? null :
        Arrays.asList(this.familyEntries);
  }
  private String defaultPolicy;
  public String getDefaultPolicy() {
    return this.defaultPolicy;
  }

  private String portList;
  public String getPortList() {
    return this.portList;
  }

  private String ipv6DefaultPolicy;
  public String getIpv6DefaultPolicy() {
    return this.ipv6DefaultPolicy;
  }

  private String ipv6PortList;
  public String getIpv6PortList() {
    return this.ipv6PortList;
  }
}

