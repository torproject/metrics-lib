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
import org.torproject.descriptor.BandwidthHistory;
import org.torproject.descriptor.ServerDescriptor;

/* Contains a relay server descriptor. */
public class ServerDescriptorImpl extends DescriptorImpl
    implements ServerDescriptor {

  protected static List<ServerDescriptor> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<ServerDescriptor> parsedDescriptors =
        new ArrayList<ServerDescriptor>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "router ");
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      ServerDescriptor parsedDescriptor =
          new ServerDescriptorImpl(descriptorBytes,
          failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected ServerDescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines, false);
    this.parseDescriptorBytes();
    this.calculateDigest();
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList(
        "router,bandwidth,published".split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList((
        "platform,fingerprint,hibernating,uptime,contact,family,"
        + "read-history,write-history,eventdns,caches-extra-info,"
        + "extra-info-digest,hidden-service-dir,protocols,"
        + "allow-single-hop-exits,onion-key,signing-key,ipv6-policy,"
        + "ntor-onion-key,router-signature").split(",")));
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
    String nextCrypto = null;
    StringBuilder crypto = null;
    while (s.hasNext()) {
      String line = s.next();
      if (line.startsWith("@")) {
        continue;
      }
      String lineNoOpt = line.startsWith("opt ") ?
          line.substring("opt ".length()) : line;
      String[] partsNoOpt = lineNoOpt.split(" ");
      String keyword = partsNoOpt[0];
      if (keyword.equals("router")) {
        this.parseRouterLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("or-address")) {
        this.parseOrAddressLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("bandwidth")) {
        this.parseBandwidthLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("platform")) {
        this.parsePlatformLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("published")) {
        this.parsePublishedLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("fingerprint")) {
        this.parseFingerprintLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("hibernating")) {
        this.parseHibernatingLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("uptime")) {
        this.parseUptimeLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("onion-key")) {
        this.parseOnionKeyLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "onion-key";
      } else if (keyword.equals("signing-key")) {
        this.parseSigningKeyLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "signing-key";
      } else if (keyword.equals("accept")) {
        this.parseAcceptLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("reject")) {
        this.parseRejectLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("router-signature")) {
        this.parseRouterSignatureLine(line, lineNoOpt, partsNoOpt);
        nextCrypto = "router-signature";
      } else if (keyword.equals("contact")) {
        this.parseContactLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("family")) {
        this.parseFamilyLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("read-history")) {
        this.parseReadHistoryLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("write-history")) {
        this.parseWriteHistoryLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("eventdns")) {
        this.parseEventdnsLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("caches-extra-info")) {
        this.parseCachesExtraInfoLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("extra-info-digest")) {
        this.parseExtraInfoDigestLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("hidden-service-dir")) {
        this.parseHiddenServiceDirLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("protocols")) {
        this.parseProtocolsLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("allow-single-hop-exits")) {
        this.parseAllowSingleHopExitsLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("dircacheport")) {
        this.parseDircacheportLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("router-digest")) {
        this.parseRouterDigestLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("ipv6-policy")) {
        this.parseIpv6PolicyLine(line, lineNoOpt, partsNoOpt);
      } else if (keyword.equals("ntor-onion-key")) {
        this.parseNtorOnionKeyLine(line, lineNoOpt, partsNoOpt);
      } else if (line.startsWith("-----BEGIN")) {
        crypto = new StringBuilder();
        crypto.append(line + "\n");
      } else if (line.startsWith("-----END")) {
        crypto.append(line + "\n");
        String cryptoString = crypto.toString();
        crypto = null;
        if (nextCrypto.equals("onion-key")) {
          this.onionKey = cryptoString;
        } else if (nextCrypto.equals("signing-key")) {
          this.signingKey = cryptoString;
        } else if (nextCrypto.equals("router-signature")) {
          this.routerSignature = cryptoString;
        } else {
          throw new DescriptorParseException("Unrecognized crypto "
              + "block in server descriptor.");
        }
        nextCrypto = null;
      } else if (crypto != null) {
        crypto.append(line + "\n");
      } else {
        ParseHelper.parseKeyword(line, partsNoOpt[0]);
        if (this.failUnrecognizedDescriptorLines) {
          throw new DescriptorParseException("Unrecognized line '"
              + line + "' in server descriptor.");
        } else {
          if (this.unrecognizedLines == null) {
            this.unrecognizedLines = new ArrayList<String>();
          }
          this.unrecognizedLines.add(line);
        }
      }
    }
  }

  private void parseRouterLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 6) {
      /* Also accept [SP|TAB]+ where we'd previously only accept SP as
       * delimiter.  This is a hotfix for #12403, because we're currently
       * not storing valid descriptors.  A better place to implement this
       * would probably be in DescriptorImpl. */
      partsNoOpt = line.startsWith("opt ") ?
          line.substring("opt ".length()).split("[ \t]+") :
          line.split("[ \t]+");
      if (partsNoOpt.length != 6) {
        throw new DescriptorParseException("Illegal line '" + line
            + "' in server descriptor.");
      }
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
    if (partsNoOpt[1].equals("1")) {
      this.hibernating = true;
    } else if (partsNoOpt[1].equals("0")) {
      this.hibernating = false;
    } else {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
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
    this.familyEntries = new ArrayList<String>();
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
          this.familyEntries.add("$" + fingerprint + separator
              + nickname);
        } else {
          this.familyEntries.add("$"
              + ParseHelper.parseTwentyByteHexString(line,
              partsNoOpt[i].substring(1)));
        }
      } else {
        this.familyEntries.add(ParseHelper.parseNickname(line,
            partsNoOpt[i]));
      }
    }
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
    if (partsNoOpt[1].equals("1")) {
      this.usesEnhancedDnsLogic = true;
    } else if (partsNoOpt[1].equals("0")) {
      this.usesEnhancedDnsLogic = false;
    } else {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
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
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.extraInfoDigest = ParseHelper.parseTwentyByteHexString(line,
        partsNoOpt[1]);
  }

  private void parseHiddenServiceDirLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    this.hiddenServiceDirVersions = new ArrayList<Integer>();
    if (partsNoOpt.length == 1) {
      this.hiddenServiceDirVersions.add(2);
    } else {
      try {
        for (int i = 1; i < partsNoOpt.length; i++) {
          this.hiddenServiceDirVersions.add(Integer.parseInt(
              partsNoOpt[i]));
        }
      } catch (NumberFormatException e) {
        throw new DescriptorParseException("Illegal value in line '"
            + line + "'.");
      }
    }
  }

  private void parseProtocolsLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    boolean isValid = true;
    this.linkProtocolVersions = new ArrayList<Integer>();
    this.circuitProtocolVersions = new ArrayList<Integer>();
    List<Integer> protocolVersions = null;
    for (int i = 1; i < partsNoOpt.length; i++) {
      String part = partsNoOpt[i];
      if (part.equals("Link")) {
        protocolVersions = this.linkProtocolVersions;
      } else if (part.equals("Circuit")) {
        protocolVersions = this.circuitProtocolVersions;
      } else if (protocolVersions == null) {
        isValid = false;
        break;
      } else {
        try {
          protocolVersions.add(Integer.parseInt(part));
        } catch (NumberFormatException e) {
          isValid = false;
          break;
        }
      }
    }
    if (protocolVersions != this.circuitProtocolVersions) {
      isValid = false;
    }
    if (!isValid) {
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
    } else if (!partsNoOpt[1].equals("accept") &&
        !partsNoOpt[1].equals("reject")) {
      isValid = false;
    } else {
      this.ipv6DefaultPolicy = partsNoOpt[1];
      this.ipv6PortList = partsNoOpt[2];
      String[] ports = partsNoOpt[2].split(",", -1);
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

  private void parseNtorOnionKeyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 2) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.ntorOnionKey = partsNoOpt[1].replaceAll("=", "");
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
        this.serverDescriptorDigest = DigestUtils.shaHex(forDigest);
      }
    } catch (UnsupportedEncodingException e) {
      /* Handle below. */
    }
    if (this.serverDescriptorDigest == null) {
      throw new DescriptorParseException("Could not calculate server "
          + "descriptor digest.");
    }
  }

  private String serverDescriptorDigest;
  public String getServerDescriptorDigest() {
    return this.serverDescriptorDigest;
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String address;
  public String getAddress() {
    return this.address;
  }

  private int orPort;
  public int getOrPort() {
    return this.orPort;
  }

  private int socksPort;
  public int getSocksPort() {
    return this.socksPort;
  }

  private int dirPort;
  public int getDirPort() {
    return this.dirPort;
  }

  private List<String> orAddresses = new ArrayList<String>();
  public List<String> getOrAddresses() {
    return new ArrayList<String>(this.orAddresses);
  }

  private int bandwidthRate;
  public int getBandwidthRate() {
    return this.bandwidthRate;
  }

  private int bandwidthBurst;
  public int getBandwidthBurst() {
    return this.bandwidthBurst;
  }

  private int bandwidthObserved;
  public int getBandwidthObserved() {
    return this.bandwidthObserved;
  }

  private String platform;
  public String getPlatform() {
    return this.platform;
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private boolean hibernating;
  public boolean isHibernating() {
    return this.hibernating;
  }

  private Long uptime;
  public Long getUptime() {
    return this.uptime;
  }

  private String onionKey;
  public String getOnionKey() {
    return this.onionKey;
  }

  private String signingKey;
  public String getSigningKey() {
    return this.signingKey;
  }

  private List<String> exitPolicyLines = new ArrayList<String>();
  public List<String> getExitPolicyLines() {
    return new ArrayList<String>(this.exitPolicyLines);
  }

  private String routerSignature;
  public String getRouterSignature() {
    return this.routerSignature;
  }

  private String contact;
  public String getContact() {
    return this.contact;
  }

  private List<String> familyEntries;
  public List<String> getFamilyEntries() {
    return this.familyEntries == null ? null :
        new ArrayList<String>(this.familyEntries);
  }

  private BandwidthHistory readHistory;
  public BandwidthHistory getReadHistory() {
    return this.readHistory;
  }

  private BandwidthHistory writeHistory;
  public BandwidthHistory getWriteHistory() {
    return this.writeHistory;
  }

  private boolean usesEnhancedDnsLogic;
  public boolean getUsesEnhancedDnsLogic() {
    return this.usesEnhancedDnsLogic;
  }

  private boolean cachesExtraInfo;
  public boolean getCachesExtraInfo() {
    return this.cachesExtraInfo;
  }

  private String extraInfoDigest;
  public String getExtraInfoDigest() {
    return this.extraInfoDigest;
  }

  private List<Integer> hiddenServiceDirVersions;
  public List<Integer> getHiddenServiceDirVersions() {
    return this.hiddenServiceDirVersions == null ? null :
        new ArrayList<Integer>(this.hiddenServiceDirVersions);
  }

  private List<Integer> linkProtocolVersions;
  public List<Integer> getLinkProtocolVersions() {
    return this.linkProtocolVersions == null ? null :
        new ArrayList<Integer>(this.linkProtocolVersions);
  }

  private List<Integer> circuitProtocolVersions;
  public List<Integer> getCircuitProtocolVersions() {
    return this.circuitProtocolVersions == null ? null :
        new ArrayList<Integer>(this.circuitProtocolVersions);
  }

  private boolean allowSingleHopExits;
  public boolean getAllowSingleHopExits() {
    return this.allowSingleHopExits;
  }

  private String ipv6DefaultPolicy;
  public String getIpv6DefaultPolicy() {
    return this.ipv6DefaultPolicy;
  }

  private String ipv6PortList;
  public String getIpv6PortList() {
    return this.ipv6PortList;
  }

  private String ntorOnionKey;
  public String getNtorOnionKey() {
    return this.ntorOnionKey;
  }
}

