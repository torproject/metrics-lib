/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DirectoryKeyCertificate;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

public class DirectoryKeyCertificateImpl extends DescriptorImpl
    implements DirectoryKeyCertificate {

  protected static List<DirectoryKeyCertificate> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<DirectoryKeyCertificate> parsedDescriptors = new ArrayList<>();
    List<byte[]> splitDescriptorsBytes =
        DirectoryKeyCertificateImpl.splitRawDescriptorBytes(
            descriptorsBytes, Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP);
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
    this.calculateDigestSha1Hex(Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP,
        NL + Key.DIR_KEY_CERTIFICATION.keyword + NL);
    Set<Key> exactlyOnceKeys = EnumSet.of(
        Key.DIR_KEY_CERTIFICATE_VERSION, Key.FINGERPRINT, Key.DIR_IDENTITY_KEY,
        Key.DIR_KEY_PUBLISHED, Key.DIR_KEY_EXPIRES, Key.DIR_SIGNING_KEY,
        Key.DIR_KEY_CERTIFICATION);
    this.checkExactlyOnceKeys(exactlyOnceKeys);
    Set<Key> atMostOnceKeys = EnumSet.of(
        Key.DIR_ADDRESS, Key.DIR_KEY_CROSSCERT);
    this.checkAtMostOnceKeys(atMostOnceKeys);
    this.checkFirstKey(Key.DIR_KEY_CERTIFICATE_VERSION);
    this.checkLastKey(Key.DIR_KEY_CERTIFICATION);
    this.clearParsedKeys();
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    Scanner scanner = new Scanner(new String(this.rawDescriptorBytes))
        .useDelimiter(NL);
    Key nextCrypto = Key.EMPTY;
    StringBuilder crypto = null;
    while (scanner.hasNext()) {
      String line = scanner.next();
      String[] parts = line.split("[ \t]+");
      Key key = Key.get(parts[0]);
      switch (key) {
        case DIR_KEY_CERTIFICATE_VERSION:
          this.parseDirKeyCertificateVersionLine(line, parts);
          break;
        case DIR_ADDRESS:
          this.parseDirAddressLine(line, parts);
          break;
        case FINGERPRINT:
          this.parseFingerprintLine(line, parts);
          break;
        case DIR_IDENTITY_KEY:
          this.parseDirIdentityKeyLine(line, parts);
          nextCrypto = key;
          break;
        case DIR_KEY_PUBLISHED:
          this.parseDirKeyPublishedLine(line, parts);
          break;
        case DIR_KEY_EXPIRES:
          this.parseDirKeyExpiresLine(line, parts);
          break;
        case DIR_SIGNING_KEY:
          this.parseDirSigningKeyLine(line, parts);
          nextCrypto = key;
          break;
        case DIR_KEY_CROSSCERT:
          this.parseDirKeyCrosscertLine(line, parts);
          nextCrypto = key;
          break;
        case DIR_KEY_CERTIFICATION:
          this.parseDirKeyCertificationLine(line, parts);
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
          switch (nextCrypto) {
            case DIR_IDENTITY_KEY:
              this.dirIdentityKey = cryptoString;
              break;
            case DIR_SIGNING_KEY:
              this.dirSigningKey = cryptoString;
              break;
            case DIR_KEY_CROSSCERT:
              this.dirKeyCrosscert = cryptoString;
              break;
            case DIR_KEY_CERTIFICATION:
              this.dirKeyCertification = cryptoString;
              break;
            default:
              throw new DescriptorParseException("Unrecognized crypto "
                  + "block in directory key certificate.");
          }
          nextCrypto = Key.EMPTY;
          break;
        default:
          if (crypto != null) {
            crypto.append(line).append(NL);
          } else {
            if (this.failUnrecognizedDescriptorLines) {
              throw new DescriptorParseException("Unrecognized line '"
                  + line + "' in directory key certificate.");
            } else {
              if (this.unrecognizedLines == null) {
                this.unrecognizedLines = new ArrayList<>();
              }
              this.unrecognizedLines.add(line);
            }
          }
      }
    }
  }

  private void parseDirKeyCertificateVersionLine(String line,
      String[] parts) throws DescriptorParseException {
    if (!line.equals(Key.DIR_KEY_CERTIFICATE_VERSION.keyword + SP + "3")) {
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
    if (!line.equals(Key.DIR_IDENTITY_KEY.keyword)) {
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
    if (!line.equals(Key.DIR_SIGNING_KEY.keyword)) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirKeyCrosscertLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals(Key.DIR_KEY_CROSSCERT.keyword)) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseDirKeyCertificationLine(String line, String[] parts)
      throws DescriptorParseException {
    if (!line.equals(Key.DIR_KEY_CERTIFICATION.keyword)) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private int dirKeyCertificateVersion;

  @Override
  public int getDirKeyCertificateVersion() {
    return this.dirKeyCertificateVersion;
  }

  private String address;

  @Override
  public String getAddress() {
    return this.address;
  }

  private int port = -1;

  @Override
  public int getPort() {
    return this.port;
  }

  private String fingerprint;

  @Override
  public String getFingerprint() {
    return this.fingerprint;
  }

  private String dirIdentityKey;

  @Override
  public String getDirIdentityKey() {
    return this.dirIdentityKey;
  }

  private long dirKeyPublishedMillis;

  @Override
  public long getDirKeyPublishedMillis() {
    return this.dirKeyPublishedMillis;
  }

  private long dirKeyExpiresMillis;

  @Override
  public long getDirKeyExpiresMillis() {
    return this.dirKeyExpiresMillis;
  }

  private String dirSigningKey;

  @Override
  public String getDirSigningKey() {
    return this.dirSigningKey;
  }

  private String dirKeyCrosscert;

  @Override
  public String getDirKeyCrosscert() {
    return this.dirKeyCrosscert;
  }

  private String dirKeyCertification;

  @Override
  public String getDirKeyCertification() {
    return this.dirKeyCertification;
  }

  @Override
  public String getCertificateDigest() {
    return this.getDigestSha1Hex();
  }
}

