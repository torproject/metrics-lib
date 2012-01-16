/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.torproject.descriptor.ServerDescriptor;
import org.torproject.descriptor.BandwidthHistory;

/* Contains a relay server descriptor. */
public class ServerDescriptorImpl extends DescriptorImpl
    implements ServerDescriptor {

  protected static List<ServerDescriptor> parseDescriptors(
      byte[] descriptorsBytes) {
    List<ServerDescriptor> parsedDescriptors =
        new ArrayList<ServerDescriptor>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "router ");
    try {
      for (byte[] descriptorBytes : splitDescriptorsBytes) {
        ServerDescriptor parsedDescriptor =
            new ServerDescriptorImpl(descriptorBytes);
        parsedDescriptors.add(parsedDescriptor);
      }
    } catch (DescriptorParseException e) {
      /* TODO Handle this error somehow. */
      System.err.println("Failed to parse descriptor.  Skipping.");
      e.printStackTrace();
    }
    return parsedDescriptors;
  }

  protected ServerDescriptorImpl(byte[] descriptorBytes)
      throws DescriptorParseException {
    super(descriptorBytes);
    this.parseDescriptorBytes();
    Set<String> exactlyOnceKeywords = new HashSet<String>(Arrays.asList(
        "router,bandwidth,published".split(",")));
    this.checkExactlyOnceKeywords(exactlyOnceKeywords);
    Set<String> atMostOnceKeywords = new HashSet<String>(Arrays.asList((
        "platform,fingerprint,hibernating,uptime,contact,family,"
        + "read-history,write-history,eventdns,caches-extra-info,"
        + "extra-info-digest,hidden-service-dir,protocols,"
        + "allow-single-hop-exits,onion-key,signing-key,"
        + "router-signature").split(",")));
    this.checkAtMostOnceKeywords(atMostOnceKeywords);
    this.checkFirstKeyword("router");
    if (this.getKeywordCount("accept") == 0 &&
        this.getKeywordCount("reject") == 0) {
      throw new DescriptorParseException("Either keyword 'accept' or "
          + "'reject' must be contained at least once.");
    }
    return;
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.rawDescriptorBytes)));
      String line;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("@")) {
          continue;
        }
        String lineNoOpt = line.startsWith("opt ") ?
            line.substring("opt ".length()) : line;
        String[] partsNoOpt = lineNoOpt.split(" ");
        String keyword = partsNoOpt[0];
        if (keyword.equals("router")) {
          this.parseRouterLine(line, lineNoOpt, partsNoOpt);
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
        } else if (keyword.equals("signing-key")) {
          this.parseSigningKeyLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("accept")) {
          this.parseAcceptLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("reject")) {
          this.parseRejectLine(line, lineNoOpt, partsNoOpt);
        } else if (keyword.equals("router-signature")) {
          this.parseRouterSignatureLine(line, lineNoOpt, partsNoOpt);
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
        } else if (line.startsWith("-----BEGIN")) {
          skipCrypto = true;
        } else if (line.startsWith("-----END")) {
          skipCrypto = false;
        } else if (!skipCrypto) {
          /* TODO Is throwing an exception the right thing to do here?
           * This is probably fine for development, but once the library
           * is in production use, this seems annoying.  In theory,
           * dir-spec.txt says that unknown lines should be ignored.  This
           * also applies to the other descriptors. */
          throw new DescriptorParseException("Unrecognized line '" + line
              + "'.");
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
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

  private void parseBandwidthLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    if (partsNoOpt.length != 4) {
      throw new DescriptorParseException("Wrong number of values in line "
          + "'" + line + "'.");
    }
    boolean isValid = false;
    try {
      this.bandwidthRate = Integer.parseInt(partsNoOpt[1]);
      this.bandwidthBurst = Integer.parseInt(partsNoOpt[2]);
      this.bandwidthObserved = Integer.parseInt(partsNoOpt[3]);
      if (this.bandwidthRate >= 0 && this.bandwidthBurst >= 0 &&
          this.bandwidthObserved >= 0) {
        isValid = true;
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
      this.uptime = Integer.parseInt(partsNoOpt[1]);
      if (this.uptime >= 0) {
        isValid = true;
      }
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
    /* Not parsing crypto parts (yet). */
  }

  private void parseSigningKeyLine(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    /* Not parsing crypto parts (yet). */
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
    /* Not parsing crypto parts (yet). */
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
        if (partsNoOpt[i].contains("=")) {
          String fingerprint = ParseHelper.parseTwentyByteHexString(line,
              partsNoOpt[i].substring(1, partsNoOpt[i].indexOf("=")));
          String nickname = ParseHelper.parseNickname(line,
              partsNoOpt[i].substring(partsNoOpt[i].indexOf("=") + 1));
          this.familyEntries.add("$" + fingerprint + "=" + nickname);
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
    if (partsNoOpt[1].equals("true")) {
      this.usesEnhancedDnsLogic = true;
    } else if (partsNoOpt[1].equals("false")) {
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
    List<String> partsList = Arrays.asList(partsNoOpt);
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

  private int uptime = -1;
  public int getUptime() {
    return this.uptime;
  }

  private List<String> exitPolicyLines = new ArrayList<String>();
  public List<String> getExitPolicyLines() {
    return new ArrayList<String>(this.exitPolicyLines);
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
}

