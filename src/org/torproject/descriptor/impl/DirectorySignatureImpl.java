/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import org.torproject.descriptor.DirectorySignature;

public class DirectorySignatureImpl implements DirectorySignature {

  private byte[] directorySignatureBytes;
  public byte[] getDirectorySignatureBytes() {
    return this.directorySignatureBytes;
  }

  private boolean failUnrecognizedDescriptorLines;
  private List<String> unrecognizedLines;
  protected List<String> getAndClearUnrecognizedLines() {
    List<String> lines = this.unrecognizedLines;
    this.unrecognizedLines = null;
    return lines;
  }

  protected DirectorySignatureImpl(byte[] directorySignatureBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    this.directorySignatureBytes = directorySignatureBytes;
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
    this.parseDirectorySignatureBytes();
  }

  private void parseDirectorySignatureBytes()
      throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.directorySignatureBytes)).
        useDelimiter("\n");
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      String[] parts = line.split(" ", -1);
      String keyword = parts[0];
      switch (keyword) {
      case "directory-signature":
        int algorithmOffset = 0;
        switch (parts.length) {
        case 4:
          this.algorithm = parts[1];
          algorithmOffset = 1;
          break;
        case 3:
          break;
        default:
          throw new DescriptorParseException("Illegal line '" + line
              + "'.");
        }
        this.identity = ParseHelper.parseTwentyByteHexString(line,
            parts[1 + algorithmOffset]);
        this.signingKeyDigest = ParseHelper.parseTwentyByteHexString(
            line, parts[2 + algorithmOffset]);
        break;
      case "-----BEGIN":
        crypto = new StringBuilder();
        crypto.append(line).append("\n");
        break;
      case "-----END":
        crypto.append(line).append("\n");
        String cryptoString = crypto.toString();
        crypto = null;
        this.signature = cryptoString;
        break;
      default:
        if (crypto != null) {
          crypto.append(line).append("\n");
        } else {
          if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized line '"
                + line + "' in dir-source entry.");
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

  private String algorithm = "sha1";
  public String getAlgorithm() {
    return this.algorithm;
  }

  private String identity;
  public String getIdentity() {
    return this.identity;
  }

  private String signingKeyDigest;
  public String getSigningKeyDigest() {
    return this.signingKeyDigest;
  }

  private String signature;
  public String getSignature() {
    return this.signature;
  }
}

