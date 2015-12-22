/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;


import org.junit.Test;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

/* TODO Add test cases for all lines starting with "opt ". */

/* Test parsing of network status consensuses.  The main focus is on
 * making sure that the parser is as robust as possible and doesn't break,
 * no matter what gets fed into it.  A secondary focus is to ensure that
 * a parsed consensus is fully compatible to dir-spec.txt. */
public class RelayNetworkStatusConsensusImplTest {

  /* Helper class to build a directory source based on default data and
   * modifications requested by test methods. */
  private static class DirSourceBuilder {
    private static RelayNetworkStatusConsensus
        createWithDirSource(String dirSourceString)
        throws DescriptorParseException {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.dirSources.add(dirSourceString);
      return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
          true);
    }
    private String nickname = "gabelmoo";
    private static RelayNetworkStatusConsensus
        createWithNickname(String string)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.nickname = string;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String identity = "ED03BB616EB2F60BEC80151114BB25CEF515B226";
    private static RelayNetworkStatusConsensus
        createWithIdentity(String string)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.identity = string;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String hostName = "212.112.245.170";
    private static RelayNetworkStatusConsensus
        createWithHostName(String string)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.hostName = string;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String address = "212.112.245.170";
    private static RelayNetworkStatusConsensus
        createWithAddress(String string)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.address = string;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String dirPort = "80";
    private static RelayNetworkStatusConsensus
        createWithDirPort(String string)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.dirPort = string;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String orPort = "443";
    private static RelayNetworkStatusConsensus
        createWithOrPort(String string)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.orPort = string;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String contactLine = "contact 4096R/C5AA446D Sebastian Hahn "
        + "<tor@sebastianhahn.net>";
    private static RelayNetworkStatusConsensus
        createWithContactLine(String line)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.contactLine = line;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String voteDigestLine =
        "vote-digest 0F398A5834D2C139E1D92310B09F814F243354D1";
    private static RelayNetworkStatusConsensus
        createWithVoteDigestLine(String line)
        throws DescriptorParseException {
      DirSourceBuilder dsb = new DirSourceBuilder();
      dsb.voteDigestLine = line;
      return createWithDirSource(dsb.buildDirSource());
    }
    private String buildDirSource() {
      StringBuilder sb = new StringBuilder();
      String dirSourceLine = "dir-source " + this.nickname + " "
          + this.identity + " " + this.hostName + " " + this.address + " "
          + this.dirPort + " " + this.orPort;
      sb.append(dirSourceLine).append("\n");
      if (this.contactLine != null) {
        sb.append(this.contactLine).append("\n");
      }
      if (this.voteDigestLine != null) {
        sb.append(this.voteDigestLine).append("\n");
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
    private static RelayNetworkStatusConsensus
        createWithStatusEntry(String statusEntryString)
        throws DescriptorParseException {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.statusEntries.add(statusEntryString);
      return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
          true);
    }
    private String nickname = "right2privassy3";
    private static RelayNetworkStatusConsensus
        createWithNickname(String string)
        throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.nickname = string;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String fingerprintBase64 = "ADQ6gCT3DiFHKPDFr3rODBUI8HM";
    private static RelayNetworkStatusConsensus
        createWithFingerprintBase64(String string)
        throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.fingerprintBase64 = string;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String descriptorBase64 = "Yiti+nayuT2Efe2X1+M4nslwVuU";
    private static RelayNetworkStatusConsensus
        createWithDescriptorBase64(String string)
        throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.descriptorBase64 = string;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String publishedString = "2011-11-29 21:34:27";
    private static RelayNetworkStatusConsensus
        createWithPublishedString(String string)
        throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.publishedString = string;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String address = "50.63.8.215";
    private static RelayNetworkStatusConsensus
        createWithAddress(String string) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.address = string;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String orPort = "9023";
    private static RelayNetworkStatusConsensus
        createWithOrPort(String string) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.orPort = string;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String dirPort = "0";
    private static RelayNetworkStatusConsensus
        createWithDirPort(String string) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.dirPort = string;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String sLine = "s Exit Fast Named Running Stable Valid";
    private static RelayNetworkStatusConsensus
        createWithSLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.sLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String vLine = "v Tor 0.2.1.29 (r8e9b25e6c7a2e70c)";
    private static RelayNetworkStatusConsensus
        createWithVLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.vLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String wLine = "w Bandwidth=1";
    private static RelayNetworkStatusConsensus
        createWithWLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.wLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String pLine = "p accept 80,1194,1220,1293";
    private static RelayNetworkStatusConsensus
        createWithPLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.pLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }
    private String buildStatusEntry() {
      StringBuilder sb = new StringBuilder();
      String rLine = "r " + nickname + " " + fingerprintBase64 + " "
          + descriptorBase64 + " " + publishedString + " " + address + " "
          + orPort + " " + dirPort;
      sb.append(rLine).append("\n");
      if (this.sLine != null) {
        sb.append(this.sLine).append("\n");
      }
      if (this.vLine != null) {
        sb.append(this.vLine).append("\n");
      }
      if (this.wLine != null) {
        sb.append(this.wLine).append("\n");
      }
      if (this.pLine != null) {
        sb.append(this.pLine).append("\n");
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
    private static RelayNetworkStatusConsensus
        createWithDirectorySignature(String directorySignatureString)
        throws DescriptorParseException {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.addDirectorySignature(directorySignatureString);
      return new RelayNetworkStatusConsensusImpl(cb.buildConsensus(),
          true);
    }
    private String identity = "ED03BB616EB2F60BEC80151114BB25CEF515B226";
    private static RelayNetworkStatusConsensus
        createWithIdentity(String string)
        throws DescriptorParseException {
      DirectorySignatureBuilder dsb = new DirectorySignatureBuilder();
      dsb.identity = string;
      return createWithDirectorySignature(dsb.buildDirectorySignature());
    }
    private String signingKey =
        "845CF1D0B370CA443A8579D18E7987E7E532F639";
    private static RelayNetworkStatusConsensus
        createWithSigningKey(String string)
        throws DescriptorParseException {
      DirectorySignatureBuilder dsb = new DirectorySignatureBuilder();
      dsb.signingKey = string;
      return createWithDirectorySignature(dsb.buildDirectorySignature());
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

  @Test()
  public void testSampleConsensus() throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    RelayNetworkStatusConsensus consensus =
        new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
    assertEquals(3, consensus.getNetworkStatusVersion());
    assertEquals(11, consensus.getConsensusMethod());
    assertEquals(1322643600000L, consensus.getValidAfterMillis());
    assertEquals(1322647200000L, consensus.getFreshUntilMillis());
    assertEquals(1322654400000L, consensus.getValidUntilMillis());
    assertEquals(300L, consensus.getVoteSeconds());
    assertEquals(300L, consensus.getDistSeconds());
    assertTrue(consensus.getRecommendedClientVersions().contains(
        "0.2.3.8-alpha"));
    assertTrue(consensus.getRecommendedServerVersions().contains(
        "0.2.3.8-alpha"));
    assertTrue(consensus.getKnownFlags().contains("Running"));
    assertEquals(30000, (int) consensus.getConsensusParams().get(
        "CircuitPriorityHalflifeMsec"));
    assertEquals("86.59.21.38", consensus.getDirSourceEntries().get(
        "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4").getIp());
    assertTrue(consensus.containsStatusEntry(
        "00795A6E8D91C270FC23B30F388A495553E01894"));
    assertEquals("188.177.149.216", consensus.getStatusEntry(
        "00795A6E8D91C270FC23B30F388A495553E01894").getAddress());
    assertEquals("3509BA5A624403A905C74DA5C8A0CEC9E0D3AF86",
        consensus.getDirectorySignatures().get(
        "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4").
        getSigningKeyDigest());
    assertEquals(285, (int) consensus.getBandwidthWeights().get("Wbd"));
    assertTrue(consensus.getUnrecognizedLines().isEmpty());
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNoLine()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNewLine()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNewLineSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n ");
  }

  @Test()
  public void testNetworkStatusVersionPrefixLineAtChar()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "@consensus\nnetwork-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionPrefixLine()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "directory-footer\nnetwork-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionPrefixLinePoundChar()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "#consensus\nnetwork-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNoSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionOneSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersion42()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 42");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionFourtyTwo()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version FourtyTwo");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusNoLine() throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionSpaceBefore()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        " network-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusSpaceBefore() throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine(" vote-status consensus");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusNoSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine("vote-status");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusOneSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine("vote-status ");
  }

  @Test()
  public void testVoteStatusConsensusOneSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine("vote-status consensus ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusVote() throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine("vote-status vote");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusTheMagicVoteStatus()
      throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine(
        "vote-status TheMagicVoteStatus");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodNoLine()
      throws DescriptorParseException {
    ConsensusBuilder.createWithConsensusMethodLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodNoSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodOneSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodEleven()
      throws DescriptorParseException {
    ConsensusBuilder.createWithConsensusMethodLine(
        "consensus-method eleven");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodMinusOne()
      throws DescriptorParseException {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method -1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodNinePeriod()
      throws DescriptorParseException {
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method "
        + "999999999999999999999999999999999999999999999999999999999999");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodTwoLines()
      throws DescriptorParseException {
    ConsensusBuilder.createWithConsensusMethodLine(
        "consensus-method 1\nconsensus-method 1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterNoLine() throws DescriptorParseException {
    ConsensusBuilder.createWithValidAfterLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterNoSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithValidAfterLine("valid-after");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterOneSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithValidAfterLine("valid-after ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterLongAgo() throws DescriptorParseException {
    ConsensusBuilder.createWithValidAfterLine("valid-after long ago");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterFeb30() throws DescriptorParseException {
    ConsensusBuilder.createWithValidAfterLine(
        "valid-after 2011-02-30 09:00:00");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFreshUntilNoLine() throws DescriptorParseException {
    ConsensusBuilder.createWithFreshUntilLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testFreshUntilAroundTen() throws DescriptorParseException {
    ConsensusBuilder.createWithFreshUntilLine(
        "fresh-until 2011-11-30 around ten");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidUntilTomorrowMorning()
      throws DescriptorParseException {
    ConsensusBuilder.createWithValidUntilLine(
        "valid-until tomorrow morning");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayNoLine() throws DescriptorParseException {
    ConsensusBuilder.createWithVotingDelayLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayNoSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayOneSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayTriple() throws DescriptorParseException {
    ConsensusBuilder.createWithVotingDelayLine(
        "voting-delay 300 300 300");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelaySingle() throws DescriptorParseException {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay 300");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayOneTwo() throws DescriptorParseException {
    ConsensusBuilder.createWithVotingDelayLine("voting-delay one two");
  }

  @Test()
  public void testClientServerVersionsNoLine()
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.clientVersionsLine = null;
    cb.serverVersionsLine = null;
    RelayNetworkStatusConsensus consensus =
        new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
    assertNull(consensus.getRecommendedClientVersions());
    assertNull(consensus.getRecommendedServerVersions());
  }

  @Test()
  public void testServerVersionsNoLine() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithServerVersionsLine(null);
    assertNotNull(consensus.getRecommendedClientVersions());
    assertNull(consensus.getRecommendedServerVersions());
  }

  @Test()
  public void testClientVersionsNoLine() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithClientVersionsLine(null);
    assertNull(consensus.getRecommendedClientVersions());
    assertNotNull(consensus.getRecommendedServerVersions());
  }

  @Test()
  public void testClientVersionsNoSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithClientVersionsLine("client-versions");
    assertNotNull(consensus.getRecommendedClientVersions());
    assertTrue(consensus.getRecommendedClientVersions().isEmpty());
  }

  @Test()
  public void testClientVersionsOneSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithClientVersionsLine("client-versions ");
    assertNotNull(consensus.getRecommendedClientVersions());
    assertTrue(consensus.getRecommendedClientVersions().isEmpty());
  }

  @Test(expected = DescriptorParseException.class)
  public void testClientVersionsComma() throws DescriptorParseException {
    ConsensusBuilder.createWithClientVersionsLine("client-versions ,");
  }

  @Test(expected = DescriptorParseException.class)
  public void testClientVersionsCommaVersion()
      throws DescriptorParseException {
    ConsensusBuilder.createWithClientVersionsLine(
        "client-versions ,0.2.2.34");
  }

  @Test(expected = DescriptorParseException.class)
  public void testKnownFlagsNoLine() throws DescriptorParseException {
    ConsensusBuilder.createWithKnownFlagsLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testKnownFlagsNoSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithKnownFlagsLine("known-flags");
  }

  @Test(expected = DescriptorParseException.class)
  public void testKnownFlagsOneSpace() throws DescriptorParseException {
    ConsensusBuilder.createWithKnownFlagsLine("known-flags ");
  }

  @Test()
  public void testParamsNoLine() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine(null);
    assertNull(consensus.getConsensusParams());
  }

  @Test()
  public void testParamsNoSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params");
    assertNotNull(consensus.getConsensusParams());
    assertTrue(consensus.getConsensusParams().isEmpty());
  }

  @Test()
  public void testParamsOneSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params ");
    assertNotNull(consensus.getConsensusParams());
    assertTrue(consensus.getConsensusParams().isEmpty());
  }

  @Test()
  public void testParamsThreeSpaces() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params   ");
    assertNotNull(consensus.getConsensusParams());
    assertTrue(consensus.getConsensusParams().isEmpty());
  }

  @Test(expected = DescriptorParseException.class)
  public void testParamsNoEqualSign() throws DescriptorParseException {
    ConsensusBuilder.createWithParamsLine("params key-value");
  }

  @Test(expected = DescriptorParseException.class)
  public void testParamsOneTooLargeNegative()
      throws DescriptorParseException {
    ConsensusBuilder.createWithParamsLine("params min=-2147483649");
  }

  @Test()
  public void testParamsLargestNegative()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params min=-2147483648");
    assertEquals(1, consensus.getConsensusParams().size());
    assertEquals(-2147483648,
        (int) consensus.getConsensusParams().get("min"));
  }

  @Test()
  public void testParamsLargestPositive()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params max=2147483647");
    assertEquals(1, consensus.getConsensusParams().size());
    assertEquals(2147483647,
        (int) consensus.getConsensusParams().get("max"));
  }

  @Test(expected = DescriptorParseException.class)
  public void testParamsOneTooLargePositive()
      throws DescriptorParseException {
    ConsensusBuilder.createWithParamsLine("params max=2147483648");
  }

  @Test()
  public void testDirSourceLegacyNickname()
      throws DescriptorParseException {
    DirSourceBuilder dsb = new DirSourceBuilder();
    dsb.nickname = "gabelmoo-legacy";
    dsb.identity = "81349FC1F2DBA2C2C11B45CB9706637D480AB913";
    dsb.contactLine = null;
    dsb.voteDigestLine = null;
    RelayNetworkStatusConsensus consensus =
        DirSourceBuilder.createWithDirSource(dsb.buildDirSource());
    assertEquals(3, consensus.getDirSourceEntries().size());
    assertTrue(consensus.getDirSourceEntries().get(
        "81349FC1F2DBA2C2C11B45CB9706637D480AB913").isLegacy());
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceNicknameTooLong()
      throws DescriptorParseException {
    DirSourceBuilder.createWithNickname("gabelmooisfinebutthisistoolong");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceIdentityTooShort()
      throws DescriptorParseException {
    DirSourceBuilder.createWithIdentity("ED03BB616EB2F60BEC8015111");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceIdentityTooLong()
      throws DescriptorParseException {
    DirSourceBuilder.createWithIdentity("ED03BB616EB2F60BEC8015111"
        + "4BB25CEF515B226ED03BB616EB2F60BEC8");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceAddress24() throws DescriptorParseException {
    DirSourceBuilder.createWithAddress("212.112.245");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceAddress40() throws DescriptorParseException {
    DirSourceBuilder.createWithAddress("212.112.245.170.123");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceDirPortMinusOne()
      throws DescriptorParseException {
    DirSourceBuilder.createWithDirPort("-1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceDirPort66666()
      throws DescriptorParseException {
    DirSourceBuilder.createWithDirPort("66666");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceDirPortOnions()
      throws DescriptorParseException {
    DirSourceBuilder.createWithDirPort("onions");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceOrPortOnions()
      throws DescriptorParseException {
    DirSourceBuilder.createWithOrPort("onions");
  }

  @Test()
  public void testDirSourceContactNoLine()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        DirSourceBuilder.createWithContactLine(null);
    assertNull(consensus.getDirSourceEntries().get(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226").getContactLine());
  }

  @Test()
  public void testDirSourceContactLineNoSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        DirSourceBuilder.createWithContactLine("contact");
    assertNotNull(consensus.getDirSourceEntries().get(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226").getContactLine());
  }

  @Test()
  public void testDirSourceContactLineOneSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        DirSourceBuilder.createWithContactLine("contact ");
    assertNotNull(consensus.getDirSourceEntries().get(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226").getContactLine());
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceVoteDigestNoLine()
      throws DescriptorParseException {
    DirSourceBuilder.createWithVoteDigestLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceVoteDigestLineNoSpace()
      throws DescriptorParseException {
    DirSourceBuilder.createWithVoteDigestLine("vote-digest");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceVoteDigestLineOneSpace()
      throws DescriptorParseException {
    DirSourceBuilder.createWithVoteDigestLine("vote-digest ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNicknameNotAllowedChars()
      throws DescriptorParseException {
    StatusEntryBuilder.createWithNickname("notAll()wed");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNicknameTooLong() throws DescriptorParseException {
    StatusEntryBuilder.createWithNickname("1234567890123456789tooLong");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintTooShort() throws DescriptorParseException {
    StatusEntryBuilder.createWithFingerprintBase64("TooShort");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintEndsWithEqualSign()
      throws DescriptorParseException {
    StatusEntryBuilder.createWithFingerprintBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8H=");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintTooLong() throws DescriptorParseException {
    StatusEntryBuilder.createWithFingerprintBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8HMAAAA");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDescriptorTooShort() throws DescriptorParseException {
    StatusEntryBuilder.createWithDescriptorBase64("TooShort");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDescriptorEndsWithEqualSign()
      throws DescriptorParseException {
    StatusEntryBuilder.createWithDescriptorBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8H=");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDescriptorTooLong() throws DescriptorParseException {
    StatusEntryBuilder.createWithDescriptorBase64(
        "Yiti+nayuT2Efe2X1+M4nslwVuUAAAA");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublished1960() throws DescriptorParseException {
    StatusEntryBuilder.createWithPublishedString("1960-11-29 21:34:27");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublished9999() throws DescriptorParseException {
    StatusEntryBuilder.createWithPublishedString("9999-11-29 21:34:27");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddress256() throws DescriptorParseException {
    StatusEntryBuilder.createWithAddress("256.63.8.215");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddress24() throws DescriptorParseException {
    StatusEntryBuilder.createWithAddress("50.63.8/24");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddressV6() throws DescriptorParseException {
    StatusEntryBuilder.createWithAddress("::1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testOrPort66666() throws DescriptorParseException {
    StatusEntryBuilder.createWithOrPort("66666");
  }

  @Test(expected = DescriptorParseException.class)
  public void testOrPortEighty() throws DescriptorParseException {
    StatusEntryBuilder.createWithOrPort("eighty");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirPortMinusOne() throws DescriptorParseException {
    StatusEntryBuilder.createWithDirPort("-1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirPortZero() throws DescriptorParseException {
    StatusEntryBuilder.createWithDirPort("zero");
  }

  @Test()
  public void testSLineNoSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        StatusEntryBuilder.createWithSLine("s");
    assertTrue(consensus.getStatusEntry(
        "00343A8024F70E214728F0C5AF7ACE0C1508F073").getFlags().isEmpty());
  }

  @Test()
  public void testSLineOneSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        StatusEntryBuilder.createWithSLine("s ");
    assertTrue(consensus.getStatusEntry(
        "00343A8024F70E214728F0C5AF7ACE0C1508F073").getFlags().isEmpty());
  }

  @Test(expected = DescriptorParseException.class)
  public void testTwoSLines() throws DescriptorParseException {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.sLine = sb.sLine + "\n" + sb.sLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }

  @Test(expected = DescriptorParseException.class)
  public void testWLineNoSpace() throws DescriptorParseException {
    StatusEntryBuilder.createWithWLine("w");
  }

  @Test(expected = DescriptorParseException.class)
  public void testWLineOneSpace() throws DescriptorParseException {
    StatusEntryBuilder.createWithWLine("w ");
  }

  @Test()
  public void testWLineWarpSeven() throws DescriptorParseException {
    StatusEntryBuilder.createWithWLine("w Warp=7");
  }

  @Test(expected = DescriptorParseException.class)
  public void testTwoWLines() throws DescriptorParseException {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.wLine = sb.wLine + "\n" + sb.wLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }

  @Test()
  public void testWLineUnmeasured() throws DescriptorParseException {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.wLine = "w Bandwidth=42424242 Unmeasured=1";
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    RelayNetworkStatusConsensus consensus =
        new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
    for (NetworkStatusEntry s : consensus.getStatusEntries().values()) {
      if (s.getBandwidth() == 42424242L) {
        assertTrue(s.getUnmeasured());
      }
    }
  }

  @Test()
  public void testWLineNotUnmeasured() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        StatusEntryBuilder.createWithWLine("w Bandwidth=20");
    for (NetworkStatusEntry s : consensus.getStatusEntries().values()) {
      assertFalse(s.getUnmeasured());
    }
  }

  @Test(expected = DescriptorParseException.class)
  public void testPLineNoPolicy() throws DescriptorParseException {
    StatusEntryBuilder.createWithPLine("p 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPLineNoPorts() throws DescriptorParseException {
    StatusEntryBuilder.createWithPLine("p accept");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPLineNoPolicyNoPorts() throws DescriptorParseException {
    StatusEntryBuilder.createWithPLine("p ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPLineProject() throws DescriptorParseException {
    StatusEntryBuilder.createWithPLine("p project 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testTwoPLines() throws DescriptorParseException {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.pLine = sb.pLine + "\n" + sb.pLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
  }

  @Test()
  public void testNoStatusEntries() throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.clear();
    RelayNetworkStatusConsensus consensus =
        new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
    assertFalse(consensus.containsStatusEntry(
        "00795A6E8D91C270FC23B30F388A495553E01894"));
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirectoryFooterNoLine()
      throws DescriptorParseException {
    /* This breaks, because a bandwidth-weights line without a preceding
     * directory-footer line is not allowed. */
    ConsensusBuilder.createWithDirectoryFooterLine(null);
  }

  @Test()
  public void testDirectoryFooterMissing()
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.setDirectoryFooterLine(null);
    cb.setBandwidthWeightsLine(null);
    /* This does not break, because directory footers were optional before
     * consensus method 9. */
    RelayNetworkStatusConsensus consensus =
        new RelayNetworkStatusConsensusImpl(cb.buildConsensus(), true);
    assertNull(consensus.getBandwidthWeights());
  }

  @Test()
  public void testDirectoryFooterLineSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithDirectoryFooterLine("directory-footer ");
  }

  @Test()
  public void testBandwidthWeightsNoLine()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithBandwidthWeightsLine(null);
    assertNull(consensus.getBandwidthWeights());
  }

  @Test()
  public void testBandwidthWeightsLineNoSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder.
        createWithBandwidthWeightsLine("bandwidth-weights");
    assertNotNull(consensus.getBandwidthWeights());
  }

  @Test()
  public void testBandwidthWeightsLineOneSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder.
        createWithBandwidthWeightsLine("bandwidth-weights ");
    assertNotNull(consensus.getBandwidthWeights());
  }

  @Test(expected = DescriptorParseException.class)
  public void testBandwidthWeightsLineNoEqualSign()
      throws DescriptorParseException {
    ConsensusBuilder.createWithBandwidthWeightsLine(
        "bandwidth-weights Wbd-285");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirectorySignatureIdentityTooShort()
      throws DescriptorParseException {
    DirectorySignatureBuilder.createWithIdentity("ED03BB616EB2F60");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirectorySignatureIdentityTooLong()
      throws DescriptorParseException {
    DirectorySignatureBuilder.createWithIdentity(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226ED03BB616EB2F60BEC");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirectorySignatureSigningKeyTooShort()
      throws DescriptorParseException {
    DirectorySignatureBuilder.createWithSigningKey("845CF1D0B370CA4");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirectorySignatureSigningKeyTooLong()
      throws DescriptorParseException {
    DirectorySignatureBuilder.createWithSigningKey(
        "845CF1D0B370CA443A8579D18E7987E7E532F639845CF1D0B370CA443A");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNonAsciiByte20() throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    byte[] consensusBytes = cb.buildConsensus();
    consensusBytes[20] = (byte) 200;
    new RelayNetworkStatusConsensusImpl(consensusBytes, true);
  }

  @Test(expected = DescriptorParseException.class)
  public void testNonAsciiByteMinusOne()
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.networkStatusVersionLine = "Xnetwork-status-version 3";
    byte[] consensusBytes = cb.buildConsensus();
    consensusBytes[0] = (byte) 200;
    new RelayNetworkStatusConsensusImpl(consensusBytes, true);
  }

  @Test(expected = DescriptorParseException.class)
  public void testUnrecognizedHeaderLineFail()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    ConsensusBuilder.createWithUnrecognizedHeaderLine(unrecognizedLine,
        true);
  }

  @Test()
  public void testUnrecognizedHeaderLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder.
        createWithUnrecognizedHeaderLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }

  @Test(expected = DescriptorParseException.class)
  public void testUnrecognizedDirSourceLineFail()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    ConsensusBuilder.createWithUnrecognizedDirSourceLine(unrecognizedLine,
        true);
  }

  @Test()
  public void testUnrecognizedDirSourceLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder.
        createWithUnrecognizedDirSourceLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }

  @Test(expected = DescriptorParseException.class)
  public void testUnrecognizedStatusEntryLineFail()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    ConsensusBuilder.createWithUnrecognizedStatusEntryLine(
        unrecognizedLine, true);
  }

  @Test()
  public void testUnrecognizedStatusEntryLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder.
        createWithUnrecognizedStatusEntryLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }

  @Test(expected = DescriptorParseException.class)
  public void testUnrecognizedDirectoryFooterLineFail()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    ConsensusBuilder.createWithUnrecognizedFooterLine(unrecognizedLine,
        true);
  }

  @Test()
  public void testUnrecognizedDirectoryFooterLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder.
        createWithUnrecognizedFooterLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }

  @Test(expected = DescriptorParseException.class)
  public void testUnrecognizedDirectorySignatureLineFail()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    ConsensusBuilder.createWithUnrecognizedDirectorySignatureLine(
        unrecognizedLine, true);
  }

  @Test()
  public void testUnrecognizedDirectorySignatureLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder.
        createWithUnrecognizedDirectorySignatureLine(unrecognizedLine,
        false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }
}

