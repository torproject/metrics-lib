/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

import org.apache.commons.codec.digest.DigestUtils;
import org.torproject.descriptor.DirectoryKeyCertificate;

/* TODO Add test class. */

public class DirectoryKeyCertificateImpl extends DescriptorImpl
    implements DirectoryKeyCertificate {

  protected static List<DirectoryKeyCertificate> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<DirectoryKeyCertificate> parsedDescriptors =
        new ArrayList<DirectoryKeyCertificate>();
    List<byte[]> splitDescriptorsBytes =
        DirectoryKeyCertificateImpl.splitRawDescriptorBytes(
            descriptorsBytes, "dir-key-certificate-version ");
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      DirectoryKeyCertificate parsedDescriptor =
          new DirectoryKeyCertificateImpl(descriptorBytes,
          failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected DirectoryKeyCertificateImpl(byte[] rawDescriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(rawDescriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseDescriptorBytes();
    this.calculateDigest();
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList((
        "dir-key-certificate-version,fingerprint,dir-identity-key,"
        + "dir-key-published,dir-key-expires,dir-signing-key,"
        + "dir-key-certification").split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList((
        "dir-address,dir-key-crosscert").split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkFirstKeyword("dir-key-certificate-version");
    this.checkLastKeyword("dir-key-certification");
    this.clearParsedKeywords();
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.rawDescriptorBytes)).
        useDelimiter("\n");
    String nextCrypto = null;
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ");
      String keyword = parts[0];
      if (keyword.equals("dir-key-certificate-version")) {
        this.parseDirKeyCertificateVersionLine(line, parts);
      } else if (keyword.equals("dir-address")) {
        this.parseDirAddressLine(line, parts);
      } else if (keyword.equals("fingerprint")) {
        this.parseFingerprintLine(line, parts);
      } else if (keyword.equals("dir-identity-key")) {
        this.parseDirIdentityKeyLine(line, parts);
        nextCrypto = "dir-identity-key";
      } else if (keyword.equals("dir-key-published")) {
        this.parseDirKeyPublishedLine(line, parts);
      } else if (keyword.equals("dir-key-expires")) {
        this.parseDirKeyExpiresLine(line, parts);
      } else if (keyword.equals("dir-signing-key")) {
        this.parseDirSigningKeyLine(line, parts);
        nextCrypto = "dir-signing-key";
      } else if (keyword.equals("dir-key-crosscert")) {
        this.parseDirKeyCrosscertLine(line, parts);
        nextCrypto = "dir-key-crosscert";
      } else if (keyword.equals("dir-key-certification")) {
        this.parseDirKeyCertificationLine(line, parts);
        nextCrypto = "dir-key-certification";
      } else if (line.startsWith("-----BEGIN")) {
        crypto = new StringBuilder();
        crypto.append(line + "\n");
      } else if (line.startsWith("-----END")) {
        crypto.append(line + "\n");
        String cryptoString = crypto.toString();
        crypto = null;
        if (nextCrypto.equals("dir-identity-key")) {
          this.dirIdentityKey = cryptoString;
        } else if (nextCrypto.equals("dir-signing-key")) {
          this.dirSigningKey = cryptoString;
        } else if (nextCrypto.equals("dir-key-crosscert")) {
          this.dirKeyCrosscert = cryptoString;
        } else if (nextCrypto.equals("dir-key-certification")) {
          this.dirKeyCertification = cryptoString;
        } else {
          throw new DescriptorParseException("Unrecognized crypto "
              + "block in directory key certificate.");
        }
        nextCrypto = null;
      } else if (crypto != null) {
        crypto.append(line + "\n");
      } else {
        if (this.failUnrecognizedDescriptorLines) {
          throw new DescriptorParseException("Unrecognized line '"
              + line + "' in directory key certificate.");
        } else {
          if (this.unrecognizedLines == null) {
            this.unrecognizedLines = new ArrayList<String>();
          }
          this.unrecognizedLines.add(line);
        }
      }
    }
  }

  private void parseDirKeyCertificateVersionLine(String line,
      String[] parts) throws DescriptorParseException {
    if (!line.equals("dir-key-certificate-version 3")) {
      throw new DescriptorParseException("Illegal directory key "
          + "certificate version number in line '" + line + "'.");
    }
    this.dirKeyCertificateVersion = 3;
  }

  private void parseDirAddressLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2 || parts[1].split(":").length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in directory key certificate.");
    }
    this.address = ParseHelper.parseIpv4Address(line,
        parts[1].split(":")[0]);
    this.port = ParseHelper.parsePort(line, parts[1].split(":")[1]);
  }

  private void parseFingerprintLine(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in directory key certificate.");
    }
    this.fingerprint = ParseHelper.parseTwentyByteHexString(line,
        parts[1]);
  }

  private void parseDirIdentityKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-identity-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirKeyPublishedLine(String line, String[] parts)
      throws DescriptorParseException {
    this.dirKeyPublishedMillis = ParseHelper.parseTimestampAtIndex(line,
        parts, 1, 2);
  }

  private void parseDirKeyExpiresLine(String line, String[] parts)
      throws DescriptorParseException {
    this.dirKeyExpiresMillis = ParseHelper.parseTimestampAtIndex(line,
        parts, 1, 2);
  }

  private void parseDirSigningKeyLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-signing-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirKeyCrosscertLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-key-crosscert")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirKeyCertificationLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals("dir-key-certification")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void calculateDigest() throws DescriptorParseException {
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "dir-key-certificate-version ";
      String sigToken = "\ndir-key-certification\n";
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, sig - start);
        this.certificateDigest = DigestUtils.shaHex(forDigest);
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    }
    if (this.certificateDigest == null) {
      throw new DescriptorParseException("Could not calculate "
          + "certificate digest.");
    }
  }

  private int dirKeyCertificateVersion;
  public int getDirKeyCertificateVersion() {
    return this.dirKeyCertificateVersion;
  }

  private String address;
  public String getAddress() {
    return this.address;
  }

  private int port = -1;
  public int getPort() {
    return this.port;
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private String dirIdentityKey;
  public String getDirIdentityKey() {
    return this.dirIdentityKey;
  }

  private long dirKeyPublishedMillis;
  public long getDirKeyPublishedMillis() {
    return this.dirKeyPublishedMillis;
  }

  private long dirKeyExpiresMillis;
  public long getDirKeyExpiresMillis() {
    return this.dirKeyExpiresMillis;
  }

  private String dirSigningKey;
  public String getDirSigningKey() {
    return this.dirSigningKey;
  }

  private String dirKeyCrosscert;
  public String getDirKeyCrosscert() {
    return this.dirKeyCrosscert;
  }

  private String dirKeyCertification;
  public String getDirKeyCertification() {
    return this.dirKeyCertification;
  }

  private String certificateDigest;
  public String getCertificateDigest() {
    return this.certificateDigest;
  }
}

