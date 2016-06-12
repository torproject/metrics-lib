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

import org.torproject.descriptor.BandwidthHistory;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ServerDescriptor;

/* Contains a server descriptor. */
public abstract class ServerDescriptorImpl extends DescriptorImpl
    implements ServerDescriptor {

  protected ServerDescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseDescriptorBytes();
    this.calculateDigest();
    this.calculateDigestSha256();
    Set<String> exactlyOnceKeywords = new HashSet<>(Arrays.asList(
        "router,bandwidth,published".split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<>(Arrays.asList((
        "identity-ed25519,master-key-ed25519,platform,fingerprint,"
        + "hibernating,uptime,contact,family,read-history,write-history,"
        + "eventdns,caches-extra-info,extra-info-digest,"
        + "hidden-service-dir,protocols,allow-single-hop-exits,onion-key,"
        + "signing-key,ipv6-policy,ntor-onion-key,onion-key-crosscert,"
        + "ntor-onion-key-crosscert,router-sig-ed25519,router-signature,"
        + "router-digest-sha256,router-digest").split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkFirstKeyword("router");
    if (this.getKeywordCount("accept") == 0 &&
        this.getKeywordCount("reject") == 0) {
      throw new DescriptorParseException("Either keyword 'accept' or "
          + "'reject' must be contained at least once.");
    }
    this.clearParsedKeywords();
    return;
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    Scanner s = new Scanner(new String(this.rawDescriptorBytes)).
        useDelimiter("\n");
    String nextCrypto = "";
    List<String> cryptoLines = null;
    while (s.hasNext()) {
      String line = s.next();
      if (line.startsWith("@")) {
        continue;
      }
      String lineNoOpt = line.startsWith("opt ") ?
          line.substring("opt ".length()) : line;
      String[] partsNoOpt = lineNoOpt.split("[ \t]+");
      String keyword = partsNoOpt[0];
      switch (keyword) {
      case "router":
        this.parseRouterLine(line, lineNoOpt, partsNoOpt);
        break;
      case "or-address":
        this.parseOrAddressLine(line, lineNoOpt, partsNoOpt);
        break;
      case "bandwidth":
        this.parseBandwidthLine(line, lineNoOpt, partsNoOpt);
        break;
      case "platform":
        this.parsePlatformLine(line, lineNoOpt, partsNoOpt);
        break;
      case "published":
        this.parsePublishedLine(line, lineNoOpt, partsNoOpt);
        break;
      case "fingerprint":
        this.parseFingerprintLine(line, lineNoOpt, partsNoOpt);
        break;
      case "hibernating":
        this.parseHibernatingLine(line, lineNoOpt, partsNoOpt);
        break;
      case "uptime":
        this.parseUptimeLine(line, lineNoOpt, partsNoOpt);
        break;
      case "onion-key":
        this.parseOnionKeyLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "onion-key";
        break;
      case "signing-key":
        this.parseSigningKeyLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "signing-key";
        break;
      case "accept":
        this.parseAcceptLine(line, lineNoOpt, partsNoOpt);
        break;
      case "reject":
        this.parseRejectLine(line, lineNoOpt, partsNoOpt);
        break;
      case "router-signature":
        this.parseRouterSignatureLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "router-signature";
        break;
      case "contact":
        this.parseContactLine(line, lineNoOpt, partsNoOpt);
        break;
      case "family":
        this.parseFamilyLine(line, lineNoOpt, partsNoOpt);
        break;
      case "read-history":
        this.parseReadHistoryLine(line, lineNoOpt, partsNoOpt);
        break;
      case "write-history":
        this.parseWriteHistoryLine(line, lineNoOpt, partsNoOpt);
        break;
      case "eventdns":
        this.parseEventdnsLine(line, lineNoOpt, partsNoOpt);
        break;
      case "caches-extra-info":
        this.parseCachesExtraInfoLine(line, lineNoOpt, partsNoOpt);
        break;
      case "extra-info-digest":
        this.parseExtraInfoDigestLine(line, lineNoOpt, partsNoOpt);
        break;
      case "hidden-service-dir":
        this.parseHiddenServiceDirLine(line, lineNoOpt, partsNoOpt);
        break;
      case "protocols":
        this.parseProtocolsLine(line, lineNoOpt, partsNoOpt);
        break;
      case "allow-single-hop-exits":
        this.parseAllowSingleHopExitsLine(line, lineNoOpt, partsNoOpt);
        break;
      case "dircacheport":
        this.parseDircacheportLine(line, lineNoOpt, partsNoOpt);
        break;
      case "router-digest":
        this.parseRouterDigestLine(line, lineNoOpt, partsNoOpt);
        break;
      case "router-digest-sha256":
        this.parseRouterDigestSha256Line(line, lineNoOpt, partsNoOpt);
        break;
      case "ipv6-policy":
        this.parseIpv6PolicyLine(line, lineNoOpt, partsNoOpt);
        break;
      case "ntor-onion-key":
        this.parseNtorOnionKeyLine(line, lineNoOpt, partsNoOpt);
        break;
      case "identity-ed25519":
        this.parseIdentityEd25519Line(line, lineNoOpt, partsNoOpt);
        nextCrypto = "identity-ed25519";
        break;
      case "master-key-ed25519":
        this.parseMasterKeyEd25519Line(line, lineNoOpt, partsNoOpt);
        break;
      case "router-sig-ed25519":
        this.parseRouterSigEd25519Line(line, lineNoOpt, partsNoOpt);
        break;
      case "onion-key-crosscert":
        this.parseOnionKeyCrosscert(line, lineNoOpt, partsNoOpt);
        nextCrypto = "onion-key-crosscert";
        break;
      case "ntor-onion-key-crosscert":
        this.parseNtorOnionKeyCrosscert(line, lineNoOpt, partsNoOpt);
        nextCrypto = "ntor-onion-key-crosscert";
        break;
      case "-----BEGIN":
        cryptoLines = new ArrayList<>();
        cryptoLines.add(line);
        break;
      case "-----END":
        cryptoLines.add(line);
        StringBuilder sb = new StringBuilder();
        for (String cryptoLine : cryptoLines) {
          sb.append("\n").append(cryptoLine);
        }
        String cryptoString = sb.toString().substring(1);
        switch (nextCrypto) {
        case "onion-key":
          this.onionKey = cryptoString;
          break;
        case "signing-key":
          this.signingKey = cryptoString;
          break;
        case "router-signature":
          this.routerSignature = cryptoString;
          break;
        case "identity-ed25519":
          this.identityEd25519 = cryptoString;
          this.parseIdentityEd25519CryptoBlock(cryptoString);
          break;
        case "onion-key-crosscert":
          this.onionKeyCrosscert = cryptoString;
          break;
        case "ntor-onion-key-crosscert":
          this.ntorOnionKeyCrosscert = cryptoString;
          break;
        default:
          if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized crypto "
                + "block '" + cryptoString + "' in server descriptor.");
          } else {
            if (this.unrecognizedLines == null) {
              this.unrecognizedLines = new ArrayList<>();
            }
            this.unrecognizedLines.addAll(cryptoLines);
          }
        }
        cryptoLines = null;
        nextCrypto = "";
        break;
      default:
        if (cryptoLines != null) {
          cryptoLines.add(line);
        } else {
          ParseHelper.parseKeyword(line, partsNoOpt[0]);
          if (this.failUnrecognizedDescriptorLines) {
            throw new DescriptorParseException("Unrecognized line '"
                + line + "' in server descriptor.");
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

  private void parseRouterLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 6) {
      throw new DescriptorParseException("Illegal line '" + line
          + "' in server descriptor.");
    }
    this.nickname = ParseHelper.parseNickname(line, partsNoOpt[1]);
    this.address = ParseHelper.parseIpv4Address(line, partsNoOpt[2]);
    this.orPort = ParseHelper.parsePort(line, partsNoOpt[3]);
    this.socksPort = ParseHelper.parsePort(line, partsNoOpt[4]);
    this.dirPort = ParseHelper.parsePort(line, partsNoOpt[5]);
  }

  private void parseOrAddressLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Wrong number of values in line "
          + "'" + line + "'.");
    }
    /* TODO Add more checks. */
    /* TODO Add tests. */
    this.orAddresses.add(partsNoOpt[1]);
  }

  private void parseBandwidthLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length < 3 || partsNoOpt.length > 4) {
      throw new DescriptorParseException("Wrong number of values in line "
          + "'" + line + "'.");
    }
    boolean isValid = false;
    try {
      this.bandwidthRate = Integer.parseInt(partsNoOpt[1]);
      this.bandwidthBurst = Integer.parseInt(partsNoOpt[2]);
      if (partsNoOpt.length == 4) {
        this.bandwidthObserved = Integer.parseInt(partsNoOpt[3]);
      }
      if (this.bandwidthRate >= 0 && this.bandwidthBurst >= 0 &&
          this.bandwidthObserved >= 0) {
        isValid = true;
      }
      if (partsNoOpt.length < 4) {
        /* Tor versions 0.0.8 and older only wrote bandwidth lines with
         * rate and burst values, but no observed value. */
        this.bandwidthObserved = -1;
      }
    } catch (NumberFormatException e) {
      /* Handle below. */
    }
    if (!isValid) {
      throw new DescriptorParseException("Illegal values in line '" + line
          + "'.");
    }
  }

  private void parsePlatformLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (lineNoOpt.length() > "platform ".length()) {
      this.platform = lineNoOpt.substring("platform ".length());
    } else {
      this.platform = "";
    }
  }

  private void parsePublishedLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.publishedMillis = ParseHelper.parseTimestampAtIndex(line,
        partsNoOpt, 1, 2);
  }

  private void parseFingerprintLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (lineNoOpt.length() != "fingerprint".length() + 5 * 10) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.fingerprint = ParseHelper.parseTwentyByteHexString(line,
        lineNoOpt.substring("fingerprint ".length()).replaceAll(" ", ""));
  }

  private void parseHibernatingLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.hibernating = ParseHelper.parseBoolean(partsNoOpt[1], line);
  }

  private void parseUptimeLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Wrong number of values in line "
          + "'" + line + "'.");
    }
    boolean isValid = false;
    try {
      this.uptime = Long.parseLong(partsNoOpt[1]);
      isValid = true;
    } catch (NumberFormatException e) {
      /* Handle below. */
    }
    if (!isValid) {
      throw new DescriptorParseException("Illegal value in line '" + line
          + "'.");
    }
  }

  private void parseOnionKeyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("onion-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseSigningKeyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("signing-key")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseAcceptLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.parseExitPolicyLine(line, lineNoOpt, partsNoOpt);
  }

  private void parseRejectLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.parseExitPolicyLine(line, lineNoOpt, partsNoOpt);
  }

  private void parseExitPolicyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    ParseHelper.parseExitPattern(line, partsNoOpt[1]);
    this.exitPolicyLines.add(lineNoOpt);
  }

  private void parseRouterSignatureLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("router-signature")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseContactLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (lineNoOpt.length() > "contact ".length()) {
      this.contact = lineNoOpt.substring("contact ".length());
    } else {
      this.contact = "";
    }
  }

  private void parseFamilyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    String[] familyEntries = new String[partsNoOpt.length - 1];
    for (int i = 1; i < partsNoOpt.length; i++) {
      if (partsNoOpt[i].startsWith("$")) {
        if (partsNoOpt[i].contains("=") ^ partsNoOpt[i].contains("~")) {
          String separator = partsNoOpt[i].contains("=") ? "=" : "~";
          String fingerprint = ParseHelper.parseTwentyByteHexString(line,
              partsNoOpt[i].substring(1, partsNoOpt[i].indexOf(
              separator)));
          String nickname = ParseHelper.parseNickname(line,
              partsNoOpt[i].substring(partsNoOpt[i].indexOf(
              separator) + 1));
          familyEntries[i - 1] = "$" + fingerprint + separator + nickname;
        } else {
          familyEntries[i - 1] = "$"
              + ParseHelper.parseTwentyByteHexString(line,
              partsNoOpt[i].substring(1));
        }
      } else {
        familyEntries[i - 1] = ParseHelper.parseNickname(line,
            partsNoOpt[i]);
      }
    }
    this.familyEntries = familyEntries;
  }

  private void parseReadHistoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.readHistory = new BandwidthHistoryImpl(line, lineNoOpt,
        partsNoOpt);
  }

  private void parseWriteHistoryLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.writeHistory = new BandwidthHistoryImpl(line, lineNoOpt,
        partsNoOpt);
  }

  private void parseEventdnsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.usesEnhancedDnsLogic = ParseHelper.parseBoolean(partsNoOpt[1], line);
  }

  private void parseCachesExtraInfoLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("caches-extra-info")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.cachesExtraInfo = true;
  }

  private void parseExtraInfoDigestLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length < 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.extraInfoDigest = ParseHelper.parseTwentyByteHexString(line,
        partsNoOpt[1]);
    if (partsNoOpt.length >= 3) {
      ParseHelper.parseThirtyTwoByteBase64String(line, partsNoOpt[2]);
      this.extraInfoDigestSha256 = partsNoOpt[2];
    }
  }

  private void parseHiddenServiceDirLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length == 1) {
      this.hiddenServiceDirVersions = new Integer[] { 2 };
    } else {
      try {
        Integer[] result = new Integer[partsNoOpt.length - 1];
        for (int i = 1; i < partsNoOpt.length; i++) {
          result[i - 1] = Integer.parseInt(partsNoOpt[i]);
        }
        this.hiddenServiceDirVersions = result;
      } catch (NumberFormatException e) {
        throw new DescriptorParseException("Illegal value in line '"
            + line + "'.");
      }
    }
  }

  private void parseProtocolsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    int linkIndex = -1, circuitIndex = -1;
    for (int i = 1; i < partsNoOpt.length; i++) {
      switch (partsNoOpt[i]) {
      case "Link":
        linkIndex = i;
        break;
      case "Circuit":
        circuitIndex = i;
        break;
      default:
        // empty
      }
    }
    if (linkIndex < 0 || circuitIndex < 0 || circuitIndex < linkIndex) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    try {
      Integer[] linkProtocolVersions =
          new Integer[circuitIndex - linkIndex - 1];
      for (int i = linkIndex + 1, j = 0; i < circuitIndex; i++, j++) {
        linkProtocolVersions[j] = Integer.parseInt(partsNoOpt[i]);
      }
      Integer[] circuitProtocolVersions =
          new Integer[partsNoOpt.length - circuitIndex - 1];
      for (int i = circuitIndex + 1, j = 0; i < partsNoOpt.length;
          i++, j++) {
        circuitProtocolVersions[j] = Integer.parseInt(partsNoOpt[i]);
      }
      this.linkProtocolVersions = linkProtocolVersions;
      this.circuitProtocolVersions = circuitProtocolVersions;
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseAllowSingleHopExitsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (!lineNoOpt.equals("allow-single-hop-exits")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.allowSingleHopExits = true;
  }

  private void parseDircacheportLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* The dircacheport line was only contained in server descriptors
     * published by Tor 0.0.8 and before.  It's only specified in old
     * tor-spec.txt versions. */
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    if (this.dirPort != 0) {
      throw new DescriptorParseException("At most one of dircacheport "
          + "and the directory port in the router line may be non-zero.");
    }
    this.dirPort = ParseHelper.parsePort(line, partsNoOpt[1]);
  }

  private void parseRouterDigestLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.serverDescriptorDigest = ParseHelper.parseTwentyByteHexString(
        line, partsNoOpt[1]);
  }

  private void parseIpv6PolicyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    boolean isValid = true;
    if (partsNoOpt.length != 3) {
      isValid = false;
    } else {
        switch (partsNoOpt[1]) {
        case "accept":
        case "reject":
          this.ipv6DefaultPolicy = partsNoOpt[1];
          this.ipv6PortList = partsNoOpt[2];
          String[] ports = partsNoOpt[2].split(",", -1);
          for (int i = 0; i < ports.length; i++) {
            if (ports[i].length() < 1) {
              isValid = false;
              break;
            }
          }
          break;
        default:
          isValid = false;
        }
    }
    if (!isValid) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseNtorOnionKeyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.ntorOnionKey = partsNoOpt[1].replaceAll("=", "");
  }

  private void parseIdentityEd25519Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 1) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseOnionKeyCrosscert(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 1) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseNtorOnionKeyCrosscert(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    try {
      this.ntorOnionKeyCrosscertSign = Integer.parseInt(partsNoOpt[1]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
  }

  private void parseIdentityEd25519CryptoBlock(String cryptoString)
      throws DescriptorParseException {
    String masterKeyEd25519FromIdentityEd25519 =
        ParseHelper.parseMasterKeyEd25519FromIdentityEd25519CryptoBlock(
        cryptoString);
    if (this.masterKeyEd25519 != null && !this.masterKeyEd25519.equals(
        masterKeyEd25519FromIdentityEd25519)) {
      throw new DescriptorParseException("Mismatch between "
          + "identity-ed25519 and master-key-ed25519.");
    }
    this.masterKeyEd25519 = masterKeyEd25519FromIdentityEd25519;
  }

  private void parseMasterKeyEd25519Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    String masterKeyEd25519FromMasterKeyEd25519Line = partsNoOpt[1];
    if (this.masterKeyEd25519 != null && !masterKeyEd25519.equals(
        masterKeyEd25519FromMasterKeyEd25519Line)) {
      throw new DescriptorParseException("Mismatch between "
          + "identity-ed25519 and master-key-ed25519.");
    }
    this.masterKeyEd25519 = masterKeyEd25519FromMasterKeyEd25519Line;
  }

  private void parseRouterSigEd25519Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.routerSignatureEd25519 = partsNoOpt[1];
  }

  private void parseRouterDigestSha256Line(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    ParseHelper.parseThirtyTwoByteBase64String(line, partsNoOpt[1]);
    this.serverDescriptorDigestSha256 = partsNoOpt[1];
  }

  private void calculateDigest() throws DescriptorParseException {
    if (this.serverDescriptorDigest != null) {
      /* We already learned the descriptor digest of this bridge
       * descriptor from a "router-digest" line. */
      return;
    }
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "router ";
      String sigToken = "\nrouter-signature\n";
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start,
            forDigest, 0, sig - start);
        this.serverDescriptorDigest = DatatypeConverter.printHexBinary(
            MessageDigest.getInstance("SHA-1").digest(forDigest)).
            toLowerCase();
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    } catch (NoSuchAlgorithmException e) {
      /* Handle below. */
    }
    if (this.serverDescriptorDigest == null) {
      throw new DescriptorParseException("Could not calculate server "
          + "descriptor digest.");
    }
  }

  private void calculateDigestSha256() throws DescriptorParseException {
    if (this.serverDescriptorDigestSha256 != null) {
      /* We already learned the descriptor digest of this bridge
       * descriptor from a "router-digest-sha256" line. */
      return;
    }
    try {
      String ascii = new String(this.getRawDescriptorBytes(), "US-ASCII");
      String startToken = "router ";
      String sigToken = "\n-----END SIGNATURE-----\n";
      int start = ascii.indexOf(startToken);
      int sig = ascii.indexOf(sigToken) + sigToken.length();
      if (start >= 0 && sig >= 0 && sig > start) {
        byte[] forDigest = new byte[sig - start];
        System.arraycopy(this.getRawDescriptorBytes(), start, forDigest,
            0, sig - start);
        this.serverDescriptorDigestSha256 =
            DatatypeConverter.printBase64Binary(
            MessageDigest.getInstance("SHA-256").digest(forDigest)).
            replaceAll("=", "");
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    } catch (NoSuchAlgorithmException e) {
      /* Handle below. */
    }
    if (this.serverDescriptorDigestSha256 == null) {
      throw new DescriptorParseException("Could not calculate server "
          + "descriptor SHA-256 digest.");
    }
  }

  private String serverDescriptorDigest;
  @Override
  public String getServerDescriptorDigest() {
    return this.serverDescriptorDigest;
  }

  private String serverDescriptorDigestSha256;
  @Override
  public String getServerDescriptorDigestSha256() {
    return this.serverDescriptorDigestSha256;
  }

  private String nickname;
  @Override
  public String getNickname() {
    return this.nickname;
  }

  private String address;
  @Override
  public String getAddress() {
    return this.address;
  }

  private int orPort;
  @Override
  public int getOrPort() {
    return this.orPort;
  }

  private int socksPort;
  @Override
  public int getSocksPort() {
    return this.socksPort;
  }

  private int dirPort;
  @Override
  public int getDirPort() {
    return this.dirPort;
  }

  private List<String> orAddresses = new ArrayList<>();
  @Override
  public List<String> getOrAddresses() {
    return new ArrayList<>(this.orAddresses);
  }

  private int bandwidthRate;
  @Override
  public int getBandwidthRate() {
    return this.bandwidthRate;
  }

  private int bandwidthBurst;
  @Override
  public int getBandwidthBurst() {
    return this.bandwidthBurst;
  }

  private int bandwidthObserved;
  @Override
  public int getBandwidthObserved() {
    return this.bandwidthObserved;
  }

  private String platform;
  @Override
  public String getPlatform() {
    return this.platform;
  }

  private long publishedMillis;
  @Override
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private String fingerprint;
  @Override
  public String getFingerprint() {
    return this.fingerprint;
  }

  private boolean hibernating;
  @Override
  public boolean isHibernating() {
    return this.hibernating;
  }

  private Long uptime;
  @Override
  public Long getUptime() {
    return this.uptime;
  }

  private String onionKey;
  @Override
  public String getOnionKey() {
    return this.onionKey;
  }

  private String signingKey;
  @Override
  public String getSigningKey() {
    return this.signingKey;
  }

  private List<String> exitPolicyLines = new ArrayList<>();
  @Override
  public List<String> getExitPolicyLines() {
    return new ArrayList<>(this.exitPolicyLines);
  }

  private String routerSignature;
  @Override
  public String getRouterSignature() {
    return this.routerSignature;
  }

  private String contact;
  @Override
  public String getContact() {
    return this.contact;
  }

  private String[] familyEntries;
  @Override
  public List<String> getFamilyEntries() {
    return this.familyEntries == null ? null :
        Arrays.asList(this.familyEntries);
  }

  private BandwidthHistory readHistory;
  @Override
  public BandwidthHistory getReadHistory() {
    return this.readHistory;
  }

  private BandwidthHistory writeHistory;
  @Override
  public BandwidthHistory getWriteHistory() {
    return this.writeHistory;
  }

  private boolean usesEnhancedDnsLogic;
  @Override
  public boolean getUsesEnhancedDnsLogic() {
    return this.usesEnhancedDnsLogic;
  }

  private boolean cachesExtraInfo;
  @Override
  public boolean getCachesExtraInfo() {
    return this.cachesExtraInfo;
  }

  private String extraInfoDigest;
  @Override
  public String getExtraInfoDigest() {
    return this.extraInfoDigest;
  }

  private String extraInfoDigestSha256;
  @Override
  public String getExtraInfoDigestSha256() {
    return this.extraInfoDigestSha256;
  }

  private Integer[] hiddenServiceDirVersions;
  @Override
  public List<Integer> getHiddenServiceDirVersions() {
    return this.hiddenServiceDirVersions == null ? null :
        Arrays.asList(this.hiddenServiceDirVersions);
  }

  private Integer[] linkProtocolVersions;
  @Override
  public List<Integer> getLinkProtocolVersions() {
    return this.linkProtocolVersions == null ? null :
        Arrays.asList(this.linkProtocolVersions);
  }

  private Integer[] circuitProtocolVersions;
  @Override
  public List<Integer> getCircuitProtocolVersions() {
    return this.circuitProtocolVersions == null ? null :
        Arrays.asList(this.circuitProtocolVersions);
  }

  private boolean allowSingleHopExits;
  @Override
  public boolean getAllowSingleHopExits() {
    return this.allowSingleHopExits;
  }

  private String ipv6DefaultPolicy;
  @Override
  public String getIpv6DefaultPolicy() {
    return this.ipv6DefaultPolicy;
  }

  private String ipv6PortList;
  @Override
  public String getIpv6PortList() {
    return this.ipv6PortList;
  }

  private String ntorOnionKey;
  @Override
  public String getNtorOnionKey() {
    return this.ntorOnionKey;
  }

  private String identityEd25519;
  @Override
  public String getIdentityEd25519() {
    return this.identityEd25519;
  }

  private String masterKeyEd25519;
  @Override
  public String getMasterKeyEd25519() {
    return this.masterKeyEd25519;
  }

  private String routerSignatureEd25519;
  @Override
  public String getRouterSignatureEd25519() {
    return this.routerSignatureEd25519;
  }

  private String onionKeyCrosscert;
  @Override
  public String getOnionKeyCrosscert() {
    return this.onionKeyCrosscert;
  }

  private String ntorOnionKeyCrosscert;
  @Override
  public String getNtorOnionKeyCrosscert() {
    return this.ntorOnionKeyCrosscert;
  }

  private int ntorOnionKeyCrosscertSign = -1;
  @Override
  public int getNtorOnionKeyCrosscertSign() {
    return ntorOnionKeyCrosscertSign;
  }
}

