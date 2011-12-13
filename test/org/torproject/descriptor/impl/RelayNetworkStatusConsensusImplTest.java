/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.impl.RelayNetworkStatusConsensusImpl;

import java.util.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

/* Test parsing of network status consensuses.  The main focus is on
 * making sure that the parser is as robust as possible and doesn't break,
 * no matter what gets fed into it.  A secondary focus is to ensure that
 * a parsed consensus is fully compatible to dir-spec.txt. */
public class RelayNetworkStatusConsensusImplTest {

  /* Helper class to build a consensus based on default data and
   * modifications requested by test methods. */
  private static class ConsensusBuilder {
    private String networkStatusVersionLine = "network-status-version 3";
    private static void createWithNetworkStatusVersionLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.networkStatusVersionLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String voteStatusLine = "vote-status consensus";
    private static void createWithVoteStatusLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.voteStatusLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String consensusMethodLine = "consensus-method 11";
    private static void createWithConsensusMethodLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.consensusMethodLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String validAfterLine = "valid-after 2011-11-30 09:00:00";
    private static void createWithValidAfterLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.validAfterLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String freshUntilLine = "fresh-until 2011-11-30 10:00:00";
    private static void createWithFreshUntilLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.freshUntilLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String validUntilLine = "valid-until 2011-11-30 12:00:00";
    private static void createWithValidUntilLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.validUntilLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String votingDelayLine = "voting-delay 300 300";
    private static void createWithVotingDelayLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.votingDelayLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String clientVersionsLine = "client-versions 0.2.1.31,"
        + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";
    private static void createWithClientVersionsLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.clientVersionsLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String serverVersionsLine = "server-versions 0.2.1.31,"
        + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";
    private static void createWithServerVersionsLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.serverVersionsLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String knownFlagsLine = "known-flags Authority BadExit Exit "
        + "Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid";
    private static void createWithKnownFlagsLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.knownFlagsLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String paramsLine = "params "
        + "CircuitPriorityHalflifeMsec=30000 bwauthbestratio=1 "
        + "bwauthcircs=1 bwauthdescbw=0 bwauthkp=10000 bwauthpid=1 "
        + "bwauthtd=5000 bwauthti=50000 bwauthtidecay=5000 cbtnummodes=3 "
        + "cbtquantile=80 circwindow=1000 refuseunknownexits=1";
    private static void createWithParamsLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.paramsLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private List<String> dirSources = new ArrayList<String>();
    private List<String> statusEntries = new ArrayList<String>();
    private String directoryFooterLine = "directory-footer";
    private static void createWithDirectoryFooterLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.directoryFooterLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String bandwidthWeightsLine = "bandwidth-weights Wbd=285 "
        + "Wbe=0 Wbg=0 Wbm=10000 Wdb=10000 Web=10000 Wed=1021 Wee=10000 "
        + "Weg=1021 Wem=10000 Wgb=10000 Wgd=8694 Wgg=10000 Wgm=10000 "
        + "Wmb=10000 Wmd=285 Wme=0 Wmg=0 Wmm=10000";
    private static void createWithBandwidthWeightsLine(String line) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.bandwidthWeightsLine = line;
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private List<String> directorySignatures = new ArrayList<String>();
    private ConsensusBuilder() {
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
          + "TbOY\n"
          + "x+c30jV/qQCMamTAEDGgJTw8KghI32vytupKallI1EjCOF8UvL1UnALgpaR7"
          + "sZ3W\n"
          + "7WQZVVrWDtnYaULOEKfwnGnRC7WwE+YRSysbzwwCVs0=\n"
          + "-----END SIGNATURE-----");
      this.directorySignatures.add("directory-signature "
          + "27B6B5996C426270A5C95488AA5BCEB6BCC86956 "
          + "D5C30C15BB3F1DA27669C2D88439939E8F418FCF\n"
          + "-----BEGIN SIGNATURE-----\n"
          + "DzFPj3vyYrCv0W3r8qDPJPlmeLnadY+drjWkdOqO66Ih/hAWBb9KcBJAX1sX"
          + "aDA7\n"
          + "/iSaDhduBXuJdcu8lbmMP8d6uYBdRjHXqWDXySUZAkSfPB4JJPNGvfoQA/qe"
          + "by7E\n"
          + "5374pPPL6WwCLJHkKtk21S9oHDmFBdlZq7JWQelWlVM=\n"
          + "-----END SIGNATURE-----");
    }
    private byte[] buildConsensus() {
      StringBuilder sb = new StringBuilder();
      this.appendHeader(sb);
      this.appendBody(sb);
      this.appendFooter(sb);
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
      for (String dirSource : this.dirSources) {
        sb.append(dirSource + "\n");
      }
    }
    private void appendBody(StringBuilder sb) {
      for (String statusEntry : this.statusEntries) {
        sb.append(statusEntry + "\n");
      }
    }
    private void appendFooter(StringBuilder sb) {
      if (this.directoryFooterLine != null) {
        sb.append(this.directoryFooterLine + "\n");
      }
      if (this.bandwidthWeightsLine != null) {
        sb.append(this.bandwidthWeightsLine + "\n");
      }
      for (String directorySignature : this.directorySignatures) {
        sb.append(directorySignature + "\n");
      }
    }
  }

  /* Helper class to build a directory source based on default data and
   * modifications requested by test methods. */
  private static class DirSourceBuilder {
    private static void createWithDirSource(String dirSourceString) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.dirSources.add(dirSourceString);
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String nickname = "gabelmoo";
    private static void createWithNickname(String string) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.nickname = string;
      createWithDirSource(dsb.buildDirSource());
    }
    private String identity = "ED03BB616EB2F60BEC80151114BB25CEF515B226";
    private static void createWithIdentity(String string) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.identity = string;
      createWithDirSource(dsb.buildDirSource());
    }
    private String hostName = "212.112.245.170";
    private static void createWithHostName(String string) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.hostName = string;
      createWithDirSource(dsb.buildDirSource());
    }
    private String address = "212.112.245.170";
    private static void createWithAddress(String string) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.address = string;
      createWithDirSource(dsb.buildDirSource());
    }
    private String dirPort = "80";
    private static void createWithDirPort(String string) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.dirPort = string;
      createWithDirSource(dsb.buildDirSource());
    }
    private String orPort = "443";
    private static void createWithOrPort(String string) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.orPort = string;
      createWithDirSource(dsb.buildDirSource());
    }
    private String contactLine = "contact 4096R/C5AA446D Sebastian Hahn "
        + "<tor@sebastianhahn.net>";
    private static void createWithContactLine(String line) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.contactLine = line;
      createWithDirSource(dsb.buildDirSource());
    }
    private String voteDigestLine =
        "vote-digest 0F398A5834D2C139E1D92310B09F814F243354D1";
    private static void createWithVoteDigestLine(String line) {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.voteDigestLine = line;
      createWithDirSource(dsb.buildDirSource());
    }
    private String buildDirSource() {
      StringBuilder sb = new StringBuilder();
      String dirSourceLine = "dir-source " + this.nickname + " "
          + this.identity + " " + this.hostName + " " + this.address + " "
          + this.dirPort + " " + this.orPort;
      sb.append(dirSourceLine + "\n");
      if (this.contactLine != null) {
        sb.append(this.contactLine + "\n");
      }
      if (this.voteDigestLine != null) {
        sb.append(this.voteDigestLine + "\n");
      }
      String dirSourceWithTrailingNewLine = sb.toString();
      String dirSource = dirSourceWithTrailingNewLine.substring(0,
          dirSourceWithTrailingNewLine.length() - 1);
      return dirSource;
    }
  }

  /* Helper class to build a status entry based on default data and
   * modifications requested by test methods. */
  private static class StatusEntryBuilder {
    private static void createWithStatusEntry(String statusEntryString) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.statusEntries.add(statusEntryString);
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String nickname = "right2privassy3";
    private static void createWithNickname(String string) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.nickname = string;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String fingerprintBase64 = "ADQ6gCT3DiFHKPDFr3rODBUI8HM";
    private static void createWithFingerprintBase64(String string) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.fingerprintBase64 = string;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String descriptorBase64 = "Yiti+nayuT2Efe2X1+M4nslwVuU";
    private static void createWithDescriptorBase64(String string) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.descriptorBase64 = string;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String publishedString = "2011-11-29 21:34:27";
    private static void createWithPublishedString(String string) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.publishedString = string;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String address = "50.63.8.215";
    private static void createWithAddress(String string) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.address = string;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String orPort = "9023";
    private static void createWithOrPort(String string) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.orPort = string;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String dirPort = "0";
    private static void createWithDirPort(String string) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.dirPort = string;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String sLine = "s Exit Fast Named Running Stable Valid";
    private static void createWithSLine(String line) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.sLine = line;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String vLine = "v Tor 0.2.1.29 (r8e9b25e6c7a2e70c)";
    private static void createWithVLine(String line) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.vLine = line;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String wLine = "w Bandwidth=1";
    private static void createWithWLine(String line) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.wLine = line;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String pLine = "p accept 80,1194,1220,1293";
    private static void createWithPLine(String line) {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.pLine = line;
      createWithStatusEntry(seb.buildStatusEntry());
    }
    private String buildStatusEntry() {
      StringBuilder sb = new StringBuilder();
      String rLine = "r " + nickname + " " + fingerprintBase64 + " "
          + descriptorBase64 + " " + publishedString + " " + address + " "
          + orPort + " " + dirPort;
      sb.append(rLine + "\n");
      if (this.sLine != null) {
        sb.append(this.sLine + "\n");
      }
      if (this.vLine != null) {
        sb.append(this.vLine + "\n");
      }
      if (this.wLine != null) {
        sb.append(this.wLine + "\n");
      }
      if (this.pLine != null) {
        sb.append(this.pLine + "\n");
      }
      String statusEntryWithTrailingNewLine = sb.toString();
      String statusEntry = statusEntryWithTrailingNewLine.substring(0,
          statusEntryWithTrailingNewLine.length() - 1);
      return statusEntry;
    }
  }

  /* Helper class to build a directory signature based on default data and
   * modifications requested by test methods. */
  private static class DirectorySignatureBuilder {
    private static void createWithDirectorySignature(
        String directorySignatureString) {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.directorySignatures.add(directorySignatureString);
      new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
    }
    private String identity = "ED03BB616EB2F60BEC80151114BB25CEF515B226";
    private static void createWithIdentity(String string) {
      DirectorySignatureBuilder dsb = new DirectorySignatureBuilder();
      dsb.identity = string;
      createWithDirectorySignature(dsb.buildDirectorySignature());
    }
    private String signingKey =
        "845CF1D0B370CA443A8579D18E7987E7E532F639";
    private static void createWithSigningKey(String string) {
      DirectorySignatureBuilder dsb = new DirectorySignatureBuilder();
      dsb.signingKey = string;
      createWithDirectorySignature(dsb.buildDirectorySignature());
    }
    private String buildDirectorySignature() {
      String directorySignature = "directory-signature " + identity + " "
          + signingKey + "\n"
          + "-----BEGIN SIGNATURE-----\n"
          + "gE64+/4BH43v1+7jS9FK1tu2+94at8xhVSPn4O/PpOx7b0Yb+S1hac1QHAiS"
                + "Ll+k\n"
          + "6OiANKzhj54WHSrUswBPrOzjmKj0OhGXSAe5nHZUFX9a1MDQLDCoZBj536X9"
                + "P3JG\n"
          + "z89A+wrsN17I5490y66AEvws54BYZMbgRfp8HXn/0Ss=\n"
          + "-----END SIGNATURE-----";
      return directorySignature;
    }
  }

  /* TODO We should check this. */
  @Test()
  public void testSampleConsensus() {
    ConsensusBuilder cb = new ConsensusBuilder();
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
  }

  /* TODO Throwing a RuntimeException here (and in most places below) is
   * bad.  Maybe we should define a DescriptorParseException. */
  @Test(expected = RuntimeException.class)
  public void testNetworkStatusVersionNoLine() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testNetworkStatusVersionPrefixLineAtChar() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "@consensus\nnetwork-status-version 3");
  }

  /* TODO This doesn't break.  Should it? */
  @Test()
  public void testNetworkStatusVersionPrefixDirectoryFooter() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "directory-footer\nnetwork-status-version 3");
  }
  
  @Test(expected = RuntimeException.class)
  public void testNetworkStatusVersionPrefixLinePoundChar() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "#consensus\nnetwork-status-version 3");
  }
  
  @Test(expected = RuntimeException.class)
  public void testNetworkStatusVersionNoSpace() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version");
  }

  @Test(expected = RuntimeException.class)
  public void testNetworkStatusVersionOneSpace() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version ");
  }

  /* TODO The parser should only accept version 3 and throw an Exception
   * here. */
  @Test()
  public void testNetworkStatusVersion42() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 42");
  }

  @Test(expected = RuntimeException.class)
  public void testNetworkStatusVersionFourtyTwo() {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version FourtyTwo");
  }

  /* TODO Shouldn't this throw an exception? */
  @Test()
  public void testVoteStatusNoLine() {
    ConsensusBuilder.createWithVoteStatusLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testVoteStatusNoSpace() {
    ConsensusBuilder.createWithVoteStatusLine("vote-status");
  }

  @Test(expected = RuntimeException.class)
  public void testVoteStatusOneSpace() {
    ConsensusBuilder.createWithVoteStatusLine("vote-status ");
  }

  /* TODO Should this be accepted or not? */
  @Test(expected = RuntimeException.class)
  public void testVoteStatusConsensusOneSpace() {
    ConsensusBuilder.createWithVoteStatusLine("vote-status consensus ");
  }

  @Test(expected = RuntimeException.class)
  public void testVoteStatusVote() {
    ConsensusBuilder.createWithVoteStatusLine("vote-status vote");
  }

  @Test(expected = RuntimeException.class)
  public void testVoteStatusTheMagicVoteStatus() {
    ConsensusBuilder.createWithVoteStatusLine(
        "vote-status TheMagicVoteStatus");
  }

  @Test(expected = RuntimeException.class)
  public void testConsensusMethodNoLine() {
    ConsensusBuilder.createWithConsensusMethodLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testConsensusMethodNoSpace() {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method");
  }

  @Test(expected = RuntimeException.class)
  public void testConsensusMethodOneSpace() {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method ");
  }

  @Test(expected = RuntimeException.class)
  public void testConsensusMethodEleven() {
    ConsensusBuilder.createWithConsensusMethodLine(
        "consensus-method eleven");
  }

  /* TODO We shouldn't allow negative values here. */
  @Test()
  public void testConsensusMethodMinusOne() {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method -1");
  }

  @Test(expected = RuntimeException.class)
  public void testConsensusMethodNinePeriod() {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method "
        + "999999999999999999999999999999999999999999999999999999999999");
  }

  @Test(expected = RuntimeException.class)
  public void testValidAfterNoLine() {
    ConsensusBuilder.createWithValidAfterLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testValidAfterNoSpace() {
    ConsensusBuilder.createWithValidAfterLine("valid-after");
  }

  @Test(expected = RuntimeException.class)
  public void testValidAfterOneSpace() {
    ConsensusBuilder.createWithValidAfterLine("valid-after ");
  }

  @Test(expected = RuntimeException.class)
  public void testValidAfterLongAgo() {
    ConsensusBuilder.createWithValidAfterLine("valid-after long ago");
  }

  /* TODO Wow, this should really throw an exception! */
  @Test()
  public void testValidAfterFeb30() {
    ConsensusBuilder.createWithValidAfterLine(
        "valid-after 2011-02-30 09:00:00");
  }

  @Test(expected = RuntimeException.class)
  public void testFreshUntilNoLine() {
    ConsensusBuilder.createWithFreshUntilLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testFreshUntilAroundTen() {
    ConsensusBuilder.createWithFreshUntilLine(
        "fresh-until 2011-11-30 around ten");
  }

  @Test(expected = RuntimeException.class)
  public void testValidUntilTomorrowMorning() {
    ConsensusBuilder.createWithValidUntilLine(
        "valid-until tomorrow morning");
  }

  @Test(expected = RuntimeException.class)
  public void testVotingDelayNoLine() {
    ConsensusBuilder.createWithVotingDelayLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testVotingDelayNoSpace() {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay");
  }

  @Test(expected = RuntimeException.class)
  public void testVotingDelayOneSpace() {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay ");
  }

  /* TODO This should throw an exception. */
  @Test()
  public void testVotingDelayTriple() {
    ConsensusBuilder.createWithVotingDelayLine(
        "voting-delay 300 300 300");
  }

  /* TODO This should throw an exception. */
  @Test()
  public void testVotingDelaySingle() {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay 300");
  }

  @Test(expected = RuntimeException.class)
  public void testVotingDelayOneTwo() {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay one two");
  }

  /* TODO Should this be forbidden? */
  @Test()
  public void testClientVersionsNoLineServerVersionsNoLine() {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.clientVersionsLine = null;
    cb.serverVersionsLine = null;
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
  }

  /* TODO Should this be forbidden? */
  @Test()
  public void testServerVersionsNoLine() {
    ConsensusBuilder.createWithServerVersionsLine(null);
  }

  /* TODO Should this be forbidden? */
  @Test()
  public void testClientVersionsNoLine() {
    ConsensusBuilder.createWithClientVersionsLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testClientVersionsNoSpace() {
    ConsensusBuilder.createWithClientVersionsLine("client-versions");
  }

  @Test(expected = RuntimeException.class)
  public void testClientVersionsOneSpace() {
    ConsensusBuilder.createWithClientVersionsLine("client-versions ");
  }

  /* TODO This should be caught. */
  @Test()
  public void testClientVersionsComma() {
    ConsensusBuilder.createWithClientVersionsLine("client-versions ,");
  }

  /* TODO This should be caught. */
  @Test()
  public void testClientVersionsCommaVersion() {
    ConsensusBuilder.createWithClientVersionsLine(
        "client-versions ,0.2.2.34");
  }

  @Test(expected = RuntimeException.class)
  public void testKnownFlagsNoLine() {
    ConsensusBuilder.createWithKnownFlagsLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testKnownFlagsNoSpace() {
    ConsensusBuilder.createWithKnownFlagsLine("known-flags");
  }

  /* TODO Looks like this okay, right? */
  @Test()
  public void testKnownFlagsOneSpace() {
    ConsensusBuilder.createWithKnownFlagsLine("known-flags ");
  }

  /* TODO Make sure that the params line is optional. */
  @Test()
  public void testParamsNoLine() {
    ConsensusBuilder.createWithParamsLine(null);
  }

  /* TODO If it's okay to provide an empty params line, this one should be
   * accepted, too. */
  @Test(expected = RuntimeException.class)
  public void testParamsNoSpace() {
    ConsensusBuilder.createWithParamsLine("params");
  }

  /* TODO Is this okay? */
  @Test()
  public void testParamsOneSpace() {
    ConsensusBuilder.createWithParamsLine("params ");
  }

  /* TODO Hmm, and this is okay? */
  @Test()
  public void testParamsThreeSpaces() {
    ConsensusBuilder.createWithParamsLine("params   ");
  }

  /* TODO The error message here looked strange.  Investigate. */
  @Test(expected = RuntimeException.class)
  public void testParamsNoEqualSign() {
    ConsensusBuilder.createWithParamsLine("params key-value");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceIdentityTooShort() {
    DirSourceBuilder.createWithIdentity("ED03BB616EB2F60BEC8015111");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceIdentityTooLong() {
    DirSourceBuilder.createWithIdentity("ED03BB616EB2F60BEC8015111"
        + "4BB25CEF515B226ED03BB616EB2F60BEC8");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceAddress24() {
    DirSourceBuilder.createWithAddress("212.112.245");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceAddress40() {
    DirSourceBuilder.createWithAddress("212.112.245.170.123");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceDirPortMinusOne() {
    DirSourceBuilder.createWithDirPort("-1");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceDirPort66666() {
    DirSourceBuilder.createWithDirPort("66666");
  }

  /* TODO We should check this. */
  @Test(expected = RuntimeException.class)
  public void testDirSourceDirPortOnions() {
    DirSourceBuilder.createWithDirPort("onions");
  }

  /* TODO We should check this. */
  @Test(expected = RuntimeException.class)
  public void testDirSourceOrPortOnions() {
    DirSourceBuilder.createWithOrPort("onions");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceContactNoLine() {
    DirSourceBuilder.createWithContactLine(null);
  }

  /* TODO We should check this. */
  @Test(expected = RuntimeException.class)
  public void testDirSourceContactLineNoSpace() {
    DirSourceBuilder.createWithContactLine("contact");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceContactLineOneSpace() {
    DirSourceBuilder.createWithContactLine("contact ");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirSourceVoteDigestNoLine() {
    DirSourceBuilder.createWithVoteDigestLine(null);
  }

  /* TODO We should check this. */
  @Test(expected = RuntimeException.class)
  public void testDirSourceVoteDigestLineNoSpace() {
    DirSourceBuilder.createWithVoteDigestLine("vote-digest");
  }

  /* TODO We should check this. */
  @Test(expected = RuntimeException.class)
  public void testDirSourceVoteDigestLineOneSpace() {
    DirSourceBuilder.createWithVoteDigestLine("vote-digest ");
  }

  /* TODO We should check this. */
  @Test()
  public void testNicknameNotAllowedChars() {
    StatusEntryBuilder.createWithNickname("notAll()wed");
  }

  /* TODO We should check this. */
  @Test()
  public void testNicknameTooLong() {
    StatusEntryBuilder.createWithNickname("1234567890123456789tooLong");
  }

  /* TODO We should check this. */
  @Test()
  public void testFingerprintTooShort() {
    StatusEntryBuilder.createWithFingerprintBase64("TooShort");
  }

  /* TODO We should check this. */
  @Test()
  public void testFingerprintEndsWithEqualSign() {
    StatusEntryBuilder.createWithFingerprintBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8H=");
  }

  /* TODO We should check this. */
  @Test()
  public void testFingerprintTooLong() {
    StatusEntryBuilder.createWithFingerprintBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8HMAAAA");
  }

  /* TODO We should check this. */
  @Test()
  public void testDescriptorTooShort() {
    StatusEntryBuilder.createWithDescriptorBase64("TooShort");
  }

  /* TODO We should check this. */
  @Test()
  public void testDescriptorEndsWithEqualSign() {
    StatusEntryBuilder.createWithDescriptorBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8H=");
  }

  /* TODO We should check this. */
  @Test()
  public void testDescriptorTooLong() {
    StatusEntryBuilder.createWithDescriptorBase64(
        "Yiti+nayuT2Efe2X1+M4nslwVuUAAAA");
  }

  /* TODO We should check this. */
  @Test()
  public void testPublished1960() {
    StatusEntryBuilder.createWithPublishedString("1960-11-29 21:34:27");
  }

  /* TODO We should check this. */
  @Test()
  public void testPublished9999() {
    StatusEntryBuilder.createWithPublishedString("9999-11-29 21:34:27");
  }

  /* TODO We should check this. */
  @Test()
  public void testAddress256() {
    StatusEntryBuilder.createWithAddress("256.63.8.215");
  }

  /* TODO We should check this. */
  @Test()
  public void testAddress24() {
    StatusEntryBuilder.createWithAddress("50.63.8/24");
  }

  /* TODO We should check this. */
  @Test()
  public void testAddressV6() {
    StatusEntryBuilder.createWithAddress("::1");
  }

  /* TODO We should check this. */
  @Test()
  public void testOrPort66666() {
    StatusEntryBuilder.createWithOrPort("66666");
  }

  /* TODO We should check this. */
  @Test()
  public void testOrPortEighty() {
    StatusEntryBuilder.createWithOrPort("eighty");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirPortMinusOne() {
    StatusEntryBuilder.createWithDirPort("-1");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirPortZero() {
    StatusEntryBuilder.createWithDirPort("zero");
  }

  /* TODO We should check this. */
  @Test()
  public void testSLineNoSpace() {
    StatusEntryBuilder.createWithSLine("s");
  }

  /* TODO We should check this. */
  @Test()
  public void testSLineOneSpace() {
    StatusEntryBuilder.createWithSLine("s ");
  }

  /* TODO We should detect this. */
  @Test()
  public void testTwoSLines() {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.sLine = sb.sLine + "\n" + sb.sLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
  }

  /* TODO This is not allowed, right? */
  @Test(expected = RuntimeException.class)
  public void testWLineNoSpace() {
    StatusEntryBuilder.createWithSLine("w");
  }

  /* TODO We should check this. */
  @Test()
  public void testWLineOneSpace() {
    StatusEntryBuilder.createWithSLine("w ");
  }

  /* TODO We should check this. */
  @Test()
  public void testWLineWarpSeven() {
    StatusEntryBuilder.createWithWLine("w Warp=7");
  }

  /* TODO We should detect this. */
  @Test()
  public void testTwoWLines() {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.wLine = sb.wLine + "\n" + sb.wLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
  }

  /* TODO We should check this. */
  @Test()
  public void testPLineNoPolicy() {
    StatusEntryBuilder.createWithPLine("p 80");
  }

  /* TODO We should check this. */
  @Test()
  public void testPLineNoPorts() {
    StatusEntryBuilder.createWithPLine("p accept");
  }

  /* TODO We should check this. */
  @Test()
  public void testPLineNoPolicyNoPorts() {
    StatusEntryBuilder.createWithPLine("p ");
  }

  /* TODO We should check this. */
  @Test()
  public void testPLineProject() {
    StatusEntryBuilder.createWithPLine("p project 80");
  }

  /* TODO We should detect this. */
  @Test()
  public void testTwoPLines() {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.pLine = sb.pLine + "\n" + sb.pLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
  }

  /* TODO Should we allow this? */
  @Test(expected = RuntimeException.class)
  public void testNoStatusEntries() {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.clear();
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus());
  }

  /* TODO Why does this not break?  Ah, maybe it just leaves out one
   * status entry.  Ugh.  It should break! */
  @Test()
  public void testDirectoryFooterNoLine() {
    ConsensusBuilder.createWithDirectoryFooterLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testDirectoryFooterLineSpace() {
    ConsensusBuilder.createWithDirectoryFooterLine("directory-footer ");
  }

 /* TODO Make sure that this is really okay in the code. */
  @Test()
  public void testBandwidthWeightsNoLine() {
    ConsensusBuilder.createWithBandwidthWeightsLine(null);
  }

  @Test(expected = RuntimeException.class)
  public void testBandwidthWeightsLineNoSpace() {
    ConsensusBuilder.createWithBandwidthWeightsLine("bandwidth-weights");
  }

  /* TODO We should check this. */
  @Test()
  public void testBandwidthWeightsLineOneSpace() {
    ConsensusBuilder.createWithBandwidthWeightsLine("bandwidth-weights ");
  }

  /* TODO We should check this. */
  @Test()
  public void testBandwidthWeightsLineNoEqualSign() {
    ConsensusBuilder.createWithBandwidthWeightsLine(
        "bandwidth-weights Wbd-285");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirectorySignatureIdentityTooShort() {
    DirectorySignatureBuilder.createWithIdentity("ED03BB616EB2F60");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirectorySignatureIdentityTooLong() {
    DirectorySignatureBuilder.createWithIdentity(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226ED03BB616EB2F60BEC");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirectorySignatureSigningKeyTooShort() {
    DirectorySignatureBuilder.createWithSigningKey("845CF1D0B370CA4");
  }

  /* TODO We should check this. */
  @Test()
  public void testDirectorySignatureSigningKeyTooLong() {
    DirectorySignatureBuilder.createWithSigningKey(
        "845CF1D0B370CA443A8579D18E7987E7E532F639845CF1D0B370CA443A");
  }

  @Test(expected = RuntimeException.class)
  public void testNonAsciiByte20() {
    ConsensusBuilder cb = new ConsensusBuilder();
    byte[] consensusBytes = cb.buildConsensus();
    consensusBytes[20] = (byte) 200;
    new RelayNetworkStatusConsensusImpl(consensusBytes);
  }

  @Test(expected = RuntimeException.class)
  public void testNonAsciiByteMinusOne() {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.networkStatusVersionLine = "Xnetwork-status-version 3";
    byte[] consensusBytes = cb.buildConsensus();
    consensusBytes[0] = (byte) 200;
    new RelayNetworkStatusConsensusImpl(consensusBytes);
  }
}

