/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.util.ArrayList;
import java.util.List;

import org.torproject.descriptor.RelayNetworkStatusConsensus;

/* Helper class to build a consensus based on default data and
 * modifications requested by test methods. */
public class ConsensusBuilder {
  String networkStatusVersionLine = "network-status-version 3";
  protected static RelayNetworkStatusConsensus
      createWithNetworkStatusVersionLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.networkStatusVersionLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String voteStatusLine = "vote-status consensus";
  protected static RelayNetworkStatusConsensus
      createWithVoteStatusLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.voteStatusLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String consensusMethodLine = "consensus-method 11";
  protected static RelayNetworkStatusConsensus
      createWithConsensusMethodLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.consensusMethodLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String validAfterLine = "valid-after 2011-11-30 09:00:00";
  protected static RelayNetworkStatusConsensus
      createWithValidAfterLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.validAfterLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String freshUntilLine = "fresh-until 2011-11-30 10:00:00";
  protected static RelayNetworkStatusConsensus
      createWithFreshUntilLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.freshUntilLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String validUntilLine = "valid-until 2011-11-30 12:00:00";
  protected static RelayNetworkStatusConsensus
      createWithValidUntilLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.validUntilLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String votingDelayLine = "voting-delay 300 300";
  protected static RelayNetworkStatusConsensus
      createWithVotingDelayLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.votingDelayLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  String clientVersionsLine = "client-versions 0.2.1.31,"
      + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";
  protected static RelayNetworkStatusConsensus
      createWithClientVersionsLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.clientVersionsLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  String serverVersionsLine = "server-versions 0.2.1.31,"
      + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";
  protected static RelayNetworkStatusConsensus
      createWithServerVersionsLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.serverVersionsLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String knownFlagsLine = "known-flags Authority BadExit Exit "
      + "Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid";
  protected static RelayNetworkStatusConsensus
      createWithKnownFlagsLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.knownFlagsLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String paramsLine = "params "
      + "CircuitPriorityHalflifeMsec=30000 bwauthbestratio=1 "
      + "bwauthcircs=1 bwauthdescbw=0 bwauthkp=10000 bwauthpid=1 "
      + "bwauthtd=5000 bwauthti=50000 bwauthtidecay=5000 cbtnummodes=3 "
      + "cbtquantile=80 circwindow=1000 refuseunknownexits=1";
  protected static RelayNetworkStatusConsensus
      createWithParamsLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.paramsLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  List<String> dirSources = new ArrayList<String>();
  List<String> statusEntries = new ArrayList<String>();
  private String directoryFooterLine = "directory-footer";
  protected void setDirectoryFooterLine(String line) {
    this.directoryFooterLine = line;
  }
  protected static RelayNetworkStatusConsensus
      createWithDirectoryFooterLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.directoryFooterLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private String bandwidthWeightsLine = "bandwidth-weights Wbd=285 "
      + "Wbe=0 Wbg=0 Wbm=10000 Wdb=10000 Web=10000 Wed=1021 Wee=10000 "
      + "Weg=1021 Wem=10000 Wgb=10000 Wgd=8694 Wgg=10000 Wgm=10000 "
      + "Wmb=10000 Wmd=285 Wme=0 Wmg=0 Wmm=10000";
  protected void setBandwidthWeightsLine(String line) {
    this.bandwidthWeightsLine = line;
  }
  protected static RelayNetworkStatusConsensus
      createWithBandwidthWeightsLine(String line)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.bandwidthWeightsLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }
  private List<String> directorySignatures = new ArrayList<String>();
  protected void addDirectorySignature(String directorySignatureString) {
    this.directorySignatures.add(directorySignatureString);
  }
  private String unrecognizedHeaderLine = null;
  protected static RelayNetworkStatusConsensus
      createWithUnrecognizedHeaderLine(String line,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.unrecognizedHeaderLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
        failUnrecognizedDescriptorLines);
  }
  private String unrecognizedDirSourceLine = null;
  protected static RelayNetworkStatusConsensus
      createWithUnrecognizedDirSourceLine(String line,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.unrecognizedDirSourceLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
        failUnrecognizedDescriptorLines);
  }
  private String unrecognizedStatusEntryLine = null;
  protected static RelayNetworkStatusConsensus
      createWithUnrecognizedStatusEntryLine(String line,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.unrecognizedStatusEntryLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
        failUnrecognizedDescriptorLines);
  }
  private String unrecognizedFooterLine = null;
  protected static RelayNetworkStatusConsensus
      createWithUnrecognizedFooterLine(String line,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.unrecognizedFooterLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
        failUnrecognizedDescriptorLines);
  }
  private String unrecognizedDirectorySignatureLine = null;
  protected static RelayNetworkStatusConsensus
      createWithUnrecognizedDirectorySignatureLine(String line,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.unrecognizedDirectorySignatureLine = line;
    return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
        failUnrecognizedDescriptorLines);
  }

  protected ConsensusBuilder() {
    this.dirSources.add("dir-source tor26 "
        + "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 86.59.21.38 "
        + "86.59.21.38 80 443\ncontact Peter Palfrader\nvote-digest "
        + "0333880AA67ED7E07C11108656D0C8D6DD1C7E5D");
    this.dirSources.add("dir-source ides "
        + "27B6B5996C426270A5C95488AA5BCEB6BCC86956 216.224.124.114 "
        + "216.224.124.114 9030 9090\ncontact Mike Perry "
        + "<mikeperryTAfsckedTODorg>\nvote-digest "
        + "1A8827ECD53184F7A771EFA9B3D30DC473FE8670");
    this.statusEntries.add("r ANONIONROUTER "
        + "AHhuQ8zFQJdT8l42Axxc6m6kNwI yEMZ5B/JQixNZgC1+2rLe0pR9rU "
        + "2011-11-30 02:52:58 93.128.66.111 24051 24052\ns Exit Fast "
        + "Named Running V2Dir Valid\nv Tor 0.2.2.34\nw "
        + "Bandwidth=1100\np reject 25,119,135-139,6881-6999");
    this.statusEntries.add("r Magellan AHlabo2RwnD8I7MPOIpJVVPgGJQ "
        + "rB/7uzI4mU38bZ9cSXEy+Z/4Cuk 2011-11-30 05:37:35 "
        + "188.177.149.216 9001 9030\ns Fast Named Running V2Dir "
        + "Valid\nv Tor 0.2.2.34\nw Bandwidth=367\np reject 1-65535");
    this.directorySignatures.add("directory-signature "
        + "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 "
        + "3509BA5A624403A905C74DA5C8A0CEC9E0D3AF86\n"
        + "-----BEGIN SIGNATURE-----\n"
        + "NYRcTWAMRiYYiGW0hIbzeZKU6sefg98AwwXrQUCudO8wfA1cfgttTDoscB9I"
        + "TbOY\nr+c30jV/qQCMamTAEDGgJTw8KghI32vytupKallI1EjCOF8UvL1UnA"
        + "LgpaR7sZ3W\n7WQZVVrWDtnYaULOEKfwnGnRC7WwE+YRSysbzwwCVs0=\n"
        + "-----END SIGNATURE-----");
    this.directorySignatures.add("directory-signature "
        + "27B6B5996C426270A5C95488AA5BCEB6BCC86956 "
        + "D5C30C15BB3F1DA27669C2D88439939E8F418FCF\n"
        + "-----BEGIN SIGNATURE-----\n"
        + "DzFPj3vyYrCv0W3r8qDPJPlmeLnadY+drjWkdOqO66Ih/hAWBb9KcBJAX1sX"
        + "aDA7\n/iSaDhduBXuJdcu8lbmMP8d6uYBdRjHXqWDXySUZAkSfPB4JJPNGvf"
        + "oQA/qeby7E\n5374pPPL6WwCLJHkKtk21S9oHDmFBdlZq7JWQelWlVM=\n"
        + "-----END SIGNATURE-----");
  }
  protected byte[] buildConsensus() {
    StringBuilder sb = new StringBuilder();
    this.appendHeader(sb);
    this.appendDirSources(sb);
    this.appendStatusEntries(sb);
    this.appendFooter(sb);
    this.appendDirectorySignatures(sb);
    return sb.toString().getBytes();
  }
  private void appendHeader(StringBuilder sb) {
    if (this.networkStatusVersionLine != null) {
      sb.append(this.networkStatusVersionLine + "\n");
    }
    if (this.voteStatusLine != null) {
      sb.append(this.voteStatusLine + "\n");
    }
    if (this.consensusMethodLine != null) {
      sb.append(this.consensusMethodLine + "\n");
    }
    if (this.validAfterLine != null) {
      sb.append(this.validAfterLine + "\n");
    }
    if (this.freshUntilLine != null) {
      sb.append(this.freshUntilLine + "\n");
    }
    if (this.validUntilLine != null) {
      sb.append(this.validUntilLine + "\n");
    }
    if (this.votingDelayLine != null) {
      sb.append(this.votingDelayLine + "\n");
    }
    if (this.clientVersionsLine != null) {
      sb.append(this.clientVersionsLine + "\n");
    }
    if (this.serverVersionsLine != null) {
      sb.append(this.serverVersionsLine + "\n");
    }
    if (this.knownFlagsLine != null) {
      sb.append(this.knownFlagsLine + "\n");
    }
    if (this.paramsLine != null) {
      sb.append(this.paramsLine + "\n");
    }
    if (this.unrecognizedHeaderLine != null) {
      sb.append(this.unrecognizedHeaderLine + "\n");
    }
  }
  private void appendDirSources(StringBuilder sb) {
    for (String dirSource : this.dirSources) {
      sb.append(dirSource + "\n");
    }
    if (this.unrecognizedDirSourceLine != null) {
      sb.append(this.unrecognizedDirSourceLine + "\n");
    }
  }
  private void appendStatusEntries(StringBuilder sb) {
    for (String statusEntry : this.statusEntries) {
      sb.append(statusEntry + "\n");
    }
    if (this.unrecognizedStatusEntryLine != null) {
      sb.append(this.unrecognizedStatusEntryLine + "\n");
    }
  }
  private void appendFooter(StringBuilder sb) {
    if (this.directoryFooterLine != null) {
      sb.append(this.directoryFooterLine + "\n");
    }
    if (this.bandwidthWeightsLine != null) {
      sb.append(this.bandwidthWeightsLine + "\n");
    }
    if (this.unrecognizedFooterLine != null) {
      sb.append(this.unrecognizedFooterLine + "\n");
    }
  }
  private void appendDirectorySignatures(StringBuilder sb) {
    for (String directorySignature : this.directorySignatures) {
      sb.append(directorySignature + "\n");
    }
    if (this.unrecognizedDirectorySignatureLine != null) {
      sb.append(this.unrecognizedDirectorySignatureLine + "\n");
    }
  }
}

