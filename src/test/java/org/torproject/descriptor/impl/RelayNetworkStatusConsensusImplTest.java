/* Copyright 2011--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DirectorySignature;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;

/* TODO Add test cases for all lines starting with "opt ". */

/* Test parsing of network status consensuses.  The main focus is on
 * making sure that the parser is as robust as possible and doesn't break,
 * no matter what gets fed into it.  A secondary focus is to ensure that
 * a parsed consensus is fully compatible to dir-spec.txt. */
public class RelayNetworkStatusConsensusImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  /* Helper class to build a directory source based on default data and
   * modifications requested by test methods. */
  private static class DirSourceBuilder {

    private static RelayNetworkStatusConsensus
        createWithDirSource(String dirSourceString)
        throws DescriptorParseException {
      ConsensusBuilder cb = new ConsensusBuilder();
      cb.dirSources.add(dirSourceString);
      return cb.buildConsensus();
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
      return cb.buildConsensus();
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

    @SuppressWarnings("checkstyle:membername")
    private String sLine = "s Exit Fast Named Running Stable Valid";

    private static RelayNetworkStatusConsensus
        createWithSLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.sLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }

    @SuppressWarnings("checkstyle:membername")
    private String vLine = "v Tor 0.2.1.29 (r8e9b25e6c7a2e70c)";

    private static RelayNetworkStatusConsensus
        createWithVLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.vLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }

    private String prLine = "pr Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 "
        + "HSIntro=3 HSRend=1-2 Link=1-4 LinkAuth=1 Microdesc=1-2 Relay=1-2";

    private static RelayNetworkStatusConsensus
        createWithPrLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.prLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }

    @SuppressWarnings("checkstyle:membername")
    private String wLine = "w Bandwidth=1";

    private static RelayNetworkStatusConsensus
        createWithWLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.wLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }

    @SuppressWarnings("checkstyle:membername")
    private String pLine = "p accept 80,1194,1220,1293";

    private static RelayNetworkStatusConsensus
        createWithPLine(String line) throws DescriptorParseException {
      StatusEntryBuilder seb = new StatusEntryBuilder();
      seb.pLine = line;
      return createWithStatusEntry(seb.buildStatusEntry());
    }

    @SuppressWarnings("checkstyle:localvariablename")
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
      if (this.prLine != null) {
        sb.append(this.prLine).append("\n");
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
      return cb.buildConsensus();
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

  @Test
  public void testSampleConsensus() throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    RelayNetworkStatusConsensus consensus = cb.buildConsensus();
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
    assertTrue(consensus.getRecommendedClientProtocols().get("Cons")
        .contains(1L));
    assertFalse(consensus.getRecommendedRelayProtocols().get("Cons")
        .contains(33L));
    assertFalse(consensus.getRequiredClientProtocols().get("Relay")
        .contains(1L));
    assertTrue(consensus.getRequiredRelayProtocols().get("Relay")
        .contains(1L));
    assertEquals(30000, (int) consensus.getConsensusParams().get(
        "CircuitPriorityHalflifeMsec"));
    assertEquals("86.59.21.38", consensus.getDirSourceEntries().get(
        "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4").getHostname());
    assertEquals("86.59.21.38", consensus.getDirSourceEntries().get(
        "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4").getIp());
    assertTrue(consensus.containsStatusEntry(
        "00795A6E8D91C270FC23B30F388A495553E01894"));
    assertEquals("188.177.149.216", consensus.getStatusEntry(
        "00795A6E8D91C270FC23B30F388A495553E01894").getAddress());
    for (DirectorySignature signature : consensus.getSignatures()) {
      if ("14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4".equals(
          signature.getIdentity())) {
        assertEquals("3509BA5A624403A905C74DA5C8A0CEC9E0D3AF86",
            signature.getSigningKeyDigestSha1Hex());
      }
    }
    assertEquals(285, (int) consensus.getBandwidthWeights().get("Wbd"));
    assertTrue(consensus.getUnrecognizedLines().isEmpty());
  }

  @Test
  public void testNetworkStatusVersionNoLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'network-status-version' must be "
        + "contained in the first line.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(null);
  }

  @Test
  public void testNetworkStatusVersionNewLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Blank lines are not allowed.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n");
  }

  @Test
  public void testNetworkStatusVersionNewLineSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal keyword in line ' '.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n ");
  }

  @Test
  public void testNetworkStatusVersionPrefixLineAtChar()
      throws DescriptorParseException {
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "@consensus\nnetwork-status-version 3");
  }

  @Test
  public void testNetworkStatusVersionPrefixLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Keyword 'directory-footer' is contained 2 times, but must be "
        + "contained at most once.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "directory-footer\nnetwork-status-version 3");
  }

  @Test
  public void testNetworkStatusVersionNoSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number in line "
        + "'network-status-version'.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version");
  }

  @Test
  public void testNetworkStatusVersionOneSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number in line "
        + "'network-status-version '.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version ");
  }

  @Test
  public void testNetworkStatusVersion42()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number in line "
        + "'network-status-version 42'.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 42");
  }

  @Test
  public void testNetworkStatusVersionFourtyTwo()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number in line "
        + "'network-status-version FourtyTwo'.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        "network-status-version FourtyTwo");
  }

  @Test
  public void testVoteStatusNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'vote-status' is contained 0 times, "
        + "but must be contained exactly once.");
    ConsensusBuilder.createWithVoteStatusLine(null);
  }

  @Test
  public void testNetworkStatusVersionSpaceBefore()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal keyword in line ' network-status-version 3'.");
    ConsensusBuilder.createWithNetworkStatusVersionLine(
        " network-status-version 3");
  }

  @Test
  public void testVoteStatusSpaceBefore() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal keyword in line ' vote-status consensus'.");
    ConsensusBuilder.createWithVoteStatusLine(" vote-status consensus");
  }

  @Test
  public void testVoteStatusNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Line 'vote-status' indicates that this is not a consensus.");
    ConsensusBuilder.createWithVoteStatusLine("vote-status");
  }

  @Test
  public void testVoteStatusOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Line 'vote-status ' indicates that this is not a consensus.");
    ConsensusBuilder.createWithVoteStatusLine("vote-status ");
  }

  @Test
  public void testVoteStatusConsensusOneSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithVoteStatusLine("vote-status consensus ");
  }

  @Test
  public void testVoteStatusVote() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Line 'vote-status vote' indicates that this is not a consensus.");
    ConsensusBuilder.createWithVoteStatusLine("vote-status vote");
  }

  @Test
  public void testVoteStatusTheMagicVoteStatus()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'vote-status TheMagicVoteStatus' indicates "
        + "that this is not a consensus.");
    ConsensusBuilder.createWithVoteStatusLine(
        "vote-status TheMagicVoteStatus");
  }

  @Test
  public void testConsensusMethodNoLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'consensus-method' is contained 0 "
        + "times, but must be contained exactly once.");
    ConsensusBuilder.createWithConsensusMethodLine(null);
  }

  @Test
  public void testConsensusMethodNoSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'consensus-method' in consensus.");
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method");
  }

  @Test
  public void testConsensusMethodOneSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'consensus-method ' in consensus.");
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method ");
  }

  @Test
  public void testConsensusMethodEleven()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal consensus method number in line 'consensus-method eleven'.");
    ConsensusBuilder.createWithConsensusMethodLine(
        "consensus-method eleven");
  }

  @Test
  public void testConsensusMethodMinusOne()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal consensus method number in line "
        + "'consensus-method -1'.");
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method -1");
  }

  @Test
  public void testConsensusMethodNinePeriod()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal consensus method number in line "
        + "'consensus-method 99999999999999999999999999999999999999999999"
        + "9999999999999999'.");
    ConsensusBuilder.createWithConsensusMethodLine("consensus-method "
        + "999999999999999999999999999999999999999999999999999999999999");
  }

  @Test
  public void testConsensusMethodTwoLines()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'consensus-method' is contained 2 times,"
        + " but must be contained exactly once.");
    ConsensusBuilder.createWithConsensusMethodLine(
        "consensus-method 1\nconsensus-method 1");
  }

  @Test
  public void testValidAfterNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'valid-after' is contained 0 times, "
        + "but must be contained exactly once.");
    ConsensusBuilder.createWithValidAfterLine(null);
  }

  @Test
  public void testValidAfterNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'valid-after' does not contain a "
        + "timestamp at the expected position.");
    ConsensusBuilder.createWithValidAfterLine("valid-after");
  }

  @Test
  public void testValidAfterOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'valid-after ' does not contain a timestamp"
        + " at the expected position.");
    ConsensusBuilder.createWithValidAfterLine("valid-after ");
  }

  @Test
  public void testValidAfterLongAgo() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal timestamp format in line 'valid-after long ago'.");
    ConsensusBuilder.createWithValidAfterLine("valid-after long ago");
  }

  @Test
  public void testValidAfterFeb30() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line "
        + "'valid-after 2011-02-30 09:00:00'.");
    ConsensusBuilder.createWithValidAfterLine(
        "valid-after 2011-02-30 09:00:00");
  }

  @Test
  public void testFreshUntilNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'fresh-until' is contained 0 times, "
        + "but must be contained exactly once.");
    ConsensusBuilder.createWithFreshUntilLine(null);
  }

  @Test
  public void testFreshUntilAroundTen() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line "
        + "'fresh-until 2011-11-30 around ten'.");
    ConsensusBuilder.createWithFreshUntilLine(
        "fresh-until 2011-11-30 around ten");
  }

  @Test
  public void testValidUntilTomorrowMorning()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal timestamp format in line 'valid-until tomorrow morning'.");
    ConsensusBuilder.createWithValidUntilLine(
        "valid-until tomorrow morning");
  }

  @Test
  public void testVotingDelayNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'voting-delay' is contained 0 times, "
        + "but must be contained exactly once.");
    ConsensusBuilder.createWithVotingDelayLine(null);
  }

  @Test
  public void testVotingDelayNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Wrong number of values in line 'voting-delay'.");
    ConsensusBuilder.createWithVotingDelayLine("voting-delay");
  }

  @Test
  public void testVotingDelayOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Wrong number of values in line 'voting-delay '.");
    ConsensusBuilder.createWithVotingDelayLine("voting-delay ");
  }

  @Test
  public void testVotingDelayTriple() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Wrong number of values in line 'voting-delay 300 300 300'.");
    ConsensusBuilder.createWithVotingDelayLine(
        "voting-delay 300 300 300");
  }

  @Test
  public void testVotingDelaySingle() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Wrong number of values in line 'voting-delay 300'.");
    ConsensusBuilder.createWithVotingDelayLine("voting-delay 300");
  }

  @Test
  public void testVotingDelayOneTwo() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal values in line 'voting-delay one two'.");
    ConsensusBuilder.createWithVotingDelayLine("voting-delay one two");
  }

  @Test
  public void testClientServerVersionsNoLine()
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.clientVersionsLine = null;
    cb.serverVersionsLine = null;
    RelayNetworkStatusConsensus consensus = cb.buildConsensus();
    assertNull(consensus.getRecommendedClientVersions());
    assertNull(consensus.getRecommendedServerVersions());
  }

  @Test
  public void testServerVersionsNoLine() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithServerVersionsLine(null);
    assertNotNull(consensus.getRecommendedClientVersions());
    assertNull(consensus.getRecommendedServerVersions());
  }

  @Test
  public void testClientVersionsNoLine() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithClientVersionsLine(null);
    assertNull(consensus.getRecommendedClientVersions());
    assertNotNull(consensus.getRecommendedServerVersions());
  }

  @Test
  public void testClientVersionsNoSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithClientVersionsLine("client-versions");
    assertNotNull(consensus.getRecommendedClientVersions());
    assertTrue(consensus.getRecommendedClientVersions().isEmpty());
  }

  @Test
  public void testClientVersionsOneSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithClientVersionsLine("client-versions ");
    assertNotNull(consensus.getRecommendedClientVersions());
    assertTrue(consensus.getRecommendedClientVersions().isEmpty());
  }

  @Test
  public void testClientVersionsComma() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal versions line 'client-versions ,'.");
    ConsensusBuilder.createWithClientVersionsLine("client-versions ,");
  }

  @Test
  public void testClientVersionsCommaVersion()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal versions line 'client-versions ,0.2.2.34'.");
    ConsensusBuilder.createWithClientVersionsLine(
        "client-versions ,0.2.2.34");
  }

  @Test
  public void testRecommendedClientProtocols123()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithRecommendedClientProtocolsLine(
        "recommended-client-protocols Cons=1,2,3");
    assertEquals(new TreeSet<>(Arrays.asList(1L, 2L, 3L)),
        consensus.getRecommendedClientProtocols().get("Cons"));
  }

  @Test
  public void testRecommendedRelayProtocols134()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithRecommendedRelayProtocolsLine(
        "recommended-relay-protocols Cons=1,3-4");
    assertEquals(new TreeSet<>(Arrays.asList(1L, 3L, 4L)),
        consensus.getRecommendedRelayProtocols().get("Cons"));
  }

  @Test
  public void testRequiredClientProtocols1425()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithRequiredClientProtocolsLine(
        "required-client-protocols Cons=1-3,2-4");
    assertEquals(new TreeSet<>(Arrays.asList(
        1L, 2L, 3L, 4L)),
        consensus.getRequiredClientProtocols().get("Cons"));
  }

  @Test
  public void testRequiredRelayProtocols1111()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithRequiredRelayProtocolsLine(
        "required-relay-protocols Cons=1-1,1-1");
    assertEquals(new TreeSet<>(Arrays.asList(1L)),
        consensus.getRequiredRelayProtocols().get("Cons"));
  }

  @Test
  public void testRequiredRelayProtocolsTwice()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'required-relay-protocols' is contained "
        + "2 times, but must be contained at most once.");
    ConsensusBuilder.createWithRequiredRelayProtocolsLine(
        "required-relay-protocols Cons=1\nrequired-relay-protocols Cons=1");
  }

  @Test
  public void testPackageNone() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithPackageLines(null);
    assertNull(consensus.getPackageLines());
  }

  @Test
  public void testPackageOne() throws DescriptorParseException {
    String packageLine = "package shouldbesecond 0 http digest=digest";
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithPackageLines(packageLine);
    assertEquals(packageLine.substring("package ".length()),
        consensus.getPackageLines().get(0));
  }

  @Test
  public void testPackageTwo() throws DescriptorParseException {
    List<String> packageLines = Arrays.asList(
        "package shouldbesecond 0 http digest=digest",
        "package outoforder 0 http digest=digest");
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithPackageLines(packageLines.get(0)
        + "\n" + packageLines.get(1));
    for (int i = 0; i < packageLines.size(); i++) {
      assertEquals(packageLines.get(i).substring("package ".length()),
          consensus.getPackageLines().get(i));
    }
  }

  @Test
  public void testPackageIncomplete() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Wrong number of values in line 'package shouldbesecond 0 http'.");
    String packageLine = "package shouldbesecond 0 http";
    ConsensusBuilder.createWithPackageLines(packageLine);
  }

  @Test
  public void testKnownFlagsNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'known-flags' is contained 0 times, "
        + "but must be contained exactly once.");
    ConsensusBuilder.createWithKnownFlagsLine(null);
  }

  @Test
  public void testKnownFlagsNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("No known flags in line 'known-flags'.");
    ConsensusBuilder.createWithKnownFlagsLine("known-flags");
  }

  @Test
  public void testKnownFlagsOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("No known flags in line 'known-flags '.");
    ConsensusBuilder.createWithKnownFlagsLine("known-flags ");
  }

  @Test
  public void testParamsNoLine() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine(null);
    assertNull(consensus.getConsensusParams());
  }

  @Test
  public void testParamsNoSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params");
    assertNotNull(consensus.getConsensusParams());
    assertTrue(consensus.getConsensusParams().isEmpty());
  }

  @Test
  public void testParamsOneSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params ");
    assertNotNull(consensus.getConsensusParams());
    assertTrue(consensus.getConsensusParams().isEmpty());
  }

  @Test
  public void testParamsThreeSpaces() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params   ");
    assertNotNull(consensus.getConsensusParams());
    assertTrue(consensus.getConsensusParams().isEmpty());
  }

  @Test
  public void testParamsNoEqualSign() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'params key-value' contains an illegal "
        + "value in list element 'key-value'.");
    ConsensusBuilder.createWithParamsLine("params key-value");
  }

  @Test
  public void testParamsOneTooLargeNegative()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'params min=-2147483649' contains an "
        + "illegal value in list element 'min=-2147483649'.");
    ConsensusBuilder.createWithParamsLine("params min=-2147483649");
  }

  @Test
  public void testParamsLargestNegative()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params min=-2147483648");
    assertEquals(1, consensus.getConsensusParams().size());
    assertEquals(-2147483648,
        (int) consensus.getConsensusParams().get("min"));
  }

  @Test
  public void testParamsLargestPositive()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithParamsLine("params max=2147483647");
    assertEquals(1, consensus.getConsensusParams().size());
    assertEquals(2147483647,
        (int) consensus.getConsensusParams().get("max"));
  }

  @Test
  public void testParamsOneTooLargePositive()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'params max=2147483648' contains an illegal"
        + " value in list element 'max=2147483648'.");
    ConsensusBuilder.createWithParamsLine("params max=2147483648");
  }

  @Test
  public void testSharedRandPreviousNumRevealsOnly()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal line 'shared-rand-previous-value 8' in vote.");
    ConsensusBuilder.createWithSharedRandPreviousValueLine(
        "shared-rand-previous-value 8");
  }

  @Test
  public void testSharedRandPreviousExtraArg()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'shared-rand-current-value 8 "
        + "D88plxd8YeLfCIVAR9gjiFlWB1WqpC53kWr350o1pzw= -1.0' in vote.");
    ConsensusBuilder.createWithSharedRandCurrentValueLine(
        "shared-rand-current-value 8 "
            + "D88plxd8YeLfCIVAR9gjiFlWB1WqpC53kWr350o1pzw= -1.0");
  }

  @Test
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

  @Test
  public void testDirSourceNicknameTooLong()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal nickname in line 'dir-source "
        + "gabelmooisfinebutthisistoolong ED03BB616EB2F60BEC80151114BB25CEF5"
        + "15B226 212.112.245.170 212.112.245.170 80 443'.");
    DirSourceBuilder.createWithNickname("gabelmooisfinebutthisistoolong");
  }

  @Test
  public void testDirSourceIdentityTooShort()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC8015111 212.112.245.170 212.112.245.170 80 443'.");
    DirSourceBuilder.createWithIdentity("ED03BB616EB2F60BEC8015111");
  }

  @Test
  public void testDirSourceIdentityTooLong()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226ED03BB616EB2F60BEC8 "
        + "212.112.245.170 212.112.245.170 80 443'.");
    DirSourceBuilder.createWithIdentity("ED03BB616EB2F60BEC8015111"
        + "4BB25CEF515B226ED03BB616EB2F60BEC8");
  }

  @Test
  public void testDirSourceHostnameMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Invalid line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226  212.112.245.170 80 443'.");
    DirSourceBuilder.createWithHostName("");
  }

  @Test
  public void testDirSourceAddress24() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'212.112.245' in line 'dir-source "
        + "gabelmoo ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170 "
        + "212.112.245 80 443' is not a valid IPv4 address.");
    DirSourceBuilder.createWithAddress("212.112.245");
  }

  @Test
  public void testDirSourceAddress40() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "'212.112.245.170.123' in line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170 212.112.245"
        + ".170.123 80 443' is not a valid IPv4 address.");
    DirSourceBuilder.createWithAddress("212.112.245.170.123");
  }

  @Test
  public void testDirSourceDirPortMinusOne()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'-1' in line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170 "
        + "212.112.245.170 -1 443' is not a valid port number.");
    DirSourceBuilder.createWithDirPort("-1");
  }

  @Test
  public void testDirSourceDirPort66666()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'66666' in line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170 "
        + "212.112.245.170 66666 443' is not a valid port number.");
    DirSourceBuilder.createWithDirPort("66666");
  }

  @Test
  public void testDirSourceDirPortOnions()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'onions' in line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170 "
        + "212.112.245.170 onions 443' is not a valid port number.");
    DirSourceBuilder.createWithDirPort("onions");
  }

  @Test
  public void testDirSourceOrPortOnions()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'onions' in line 'dir-source gabelmoo "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226 212.112.245.170 "
        + "212.112.245.170 80 onions' is not a valid port number.");
    DirSourceBuilder.createWithOrPort("onions");
  }

  @Test
  public void testDirSourceContactNoLine()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        DirSourceBuilder.createWithContactLine(null);
    assertNull(consensus.getDirSourceEntries().get(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226").getContactLine());
  }

  @Test
  public void testDirSourceContactLineNoSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        DirSourceBuilder.createWithContactLine("contact");
    assertNotNull(consensus.getDirSourceEntries().get(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226").getContactLine());
  }

  @Test
  public void testDirSourceContactLineOneSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        DirSourceBuilder.createWithContactLine("contact ");
    assertNotNull(consensus.getDirSourceEntries().get(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226").getContactLine());
  }

  @Test
  public void testDirSourceVoteDigestNoLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "dir-source does not contain a 'vote-digest' line.");
    DirSourceBuilder.createWithVoteDigestLine(null);
  }

  @Test
  public void testDirSourceVoteDigestLineNoSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Invalid line 'vote-digest'.");
    DirSourceBuilder.createWithVoteDigestLine("vote-digest");
  }

  @Test
  public void testDirSourceVoteDigestLineOneSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Invalid line 'vote-digest '.");
    DirSourceBuilder.createWithVoteDigestLine("vote-digest ");
  }

  @Test
  public void testNicknameNotAllowedChars()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal nickname in line 'r notAll()wed "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 "
        + "21:34:27 50.63.8.215 9023 0'.");
    StatusEntryBuilder.createWithNickname("notAll()wed");
  }

  @Test
  public void testNicknameTooLong() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal nickname in line "
        + "'r 1234567890123456789tooLong ADQ6gCT3DiFHKPDFr3rODBUI8HM "
        + "Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 21:34:27 50.63.8.215 "
        + "9023 0'.");
    StatusEntryBuilder.createWithNickname("1234567890123456789tooLong");
  }

  @Test
  public void testFingerprintTooShort() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'TooShort' in line 'r right2privassy3 TooShort "
        + "Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 21:34:27 50.63.8.215 9023 0' "
        + "is not a valid base64-encoded 20-byte value.");
    StatusEntryBuilder.createWithFingerprintBase64("TooShort");
  }

  @Test
  public void testFingerprintEndsWithEqualSign()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'ADQ6gCT3DiFHKPDFr3rODBUI8H=' in line 'r "
        + "right2privassy3 ADQ6gCT3DiFHKPDFr3rODBUI8H= Yiti+nayuT2Efe2X1+M4"
        + "nslwVuU 2011-11-29 21:34:27 50.63.8.215 9023 0' is not a valid "
        + "base64-encoded 20-byte value.");
    StatusEntryBuilder.createWithFingerprintBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8H=");
  }

  @Test
  public void testFingerprintTooLong() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'ADQ6gCT3DiFHKPDFr3rODBUI8HMAAAA' in line "
        + "'r right2privassy3 ADQ6gCT3DiFHKPDFr3rODBUI8HMAAAA Yiti+nayuT2Efe2X1"
        + "+M4nslwVuU 2011-11-29 21:34:27 50.63.8.215 9023 0' is not a valid "
        + "base64-encoded 20-byte value.");
    StatusEntryBuilder.createWithFingerprintBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8HMAAAA");
  }

  @Test
  public void testDescriptorTooShort() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'TooShort' in line 'r right2privassy3 "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM TooShort 2011-11-29 21:34:27 50.63.8.215"
        + " 9023 0' is not a valid base64-encoded 20-byte value.");
    StatusEntryBuilder.createWithDescriptorBase64("TooShort");
  }

  @Test
  public void testDescriptorEndsWithEqualSign()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'ADQ6gCT3DiFHKPDFr3rODBUI8H=' in line "
        + "'r right2privassy3 ADQ6gCT3DiFHKPDFr3rODBUI8HM "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8H= 2011-11-29 21:34:27 50.63.8.215 9023 0' "
        + "is not a valid base64-encoded 20-byte value.");
    StatusEntryBuilder.createWithDescriptorBase64(
        "ADQ6gCT3DiFHKPDFr3rODBUI8H=");
  }

  @Test
  public void testDescriptorTooLong() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'Yiti+nayuT2Efe2X1+M4nslwVuUAAAA' in line "
        + "'r right2privassy3 ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4n"
        + "slwVuUAAAA 2011-11-29 21:34:27 50.63.8.215 9023 0' is not a valid "
        + "base64-encoded 20-byte value.");
    StatusEntryBuilder.createWithDescriptorBase64(
        "Yiti+nayuT2Efe2X1+M4nslwVuUAAAA");
  }

  @Test
  public void testPublished1960() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line 'r "
        + "right2privassy3 ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4ns"
        + "lwVuU 1960-11-29 21:34:27 50.63.8.215 9023 0'.");
    StatusEntryBuilder.createWithPublishedString("1960-11-29 21:34:27");
  }

  @Test
  public void testPublished9999() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line 'r "
        + "right2privassy3 ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+"
        + "M4nslwVuU 9999-11-29 21:34:27 50.63.8.215 9023 0'.");
    StatusEntryBuilder.createWithPublishedString("9999-11-29 21:34:27");
  }

  @Test
  public void testAddress256() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'256.63.8.215' in line 'r right2privassy3 "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 "
        + "21:34:27 256.63.8.215 9023 0' is not a valid IPv4 address.");
    StatusEntryBuilder.createWithAddress("256.63.8.215");
  }

  @Test
  public void testAddress24() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'50.63.8/24' in line 'r right2privassy3 "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 "
        + "21:34:27 50.63.8/24 9023 0' is not a valid IPv4 address.");
    StatusEntryBuilder.createWithAddress("50.63.8/24");
  }

  @Test
  public void testAddressV6() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'::1' in line 'r right2privassy3 "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 "
        + "21:34:27 ::1 9023 0' is not a valid IPv4 address.");
    StatusEntryBuilder.createWithAddress("::1");
  }

  @Test
  public void testOrPort66666() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'66666' in line 'r right2privassy3 "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 "
        + "21:34:27 50.63.8.215 66666 0' is not a valid port number.");
    StatusEntryBuilder.createWithOrPort("66666");
  }

  @Test
  public void testOrPortEighty() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'eighty' in line 'r right2privassy3 "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 "
        + "21:34:27 50.63.8.215 eighty 0' is not a valid port number.");
    StatusEntryBuilder.createWithOrPort("eighty");
  }

  @Test
  public void testDirPortMinusOne() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'-1' in line 'r right2privassy3 ADQ6gCT3DiFHKP"
        + "DFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 21:34:27 "
        + "50.63.8.215 9023 -1' is not a valid port number.");
    StatusEntryBuilder.createWithDirPort("-1");
  }

  @Test
  public void testDirPortZero() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'zero' in line 'r right2privassy3 "
        + "ADQ6gCT3DiFHKPDFr3rODBUI8HM Yiti+nayuT2Efe2X1+M4nslwVuU 2011-11-29 "
        + "21:34:27 50.63.8.215 9023 zero' is not a valid port number.");
    StatusEntryBuilder.createWithDirPort("zero");
  }

  @Test
  public void testSLineNoSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        StatusEntryBuilder.createWithSLine("s");
    assertTrue(consensus.getStatusEntry(
        "00343A8024F70E214728F0C5AF7ACE0C1508F073").getFlags().isEmpty());
  }

  @Test
  public void testSLineOneSpace() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        StatusEntryBuilder.createWithSLine("s ");
    assertTrue(consensus.getStatusEntry(
        "00343A8024F70E214728F0C5AF7ACE0C1508F073").getFlags().isEmpty());
  }

  @Test
  public void testTwoSLines() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Duplicate 's' line in status entry.");
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.sLine = sb.sLine + "\n" + sb.sLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    cb.buildConsensus();
  }

  @Test
  public void testTwoPrLines() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Duplicate 'pr' line in status entry.");
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.prLine = sb.prLine + "\n" + sb.prLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    cb.buildConsensus();
  }

  @Test
  public void testWLineNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'w'.");
    StatusEntryBuilder.createWithWLine("w");
  }

  @Test
  public void testWLineOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'w '.");
    StatusEntryBuilder.createWithWLine("w ");
  }

  @Test
  public void testWLineWarpSeven() throws DescriptorParseException {
    StatusEntryBuilder.createWithWLine("w Warp=7");
  }

  @Test
  public void testTwoWLines() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Duplicate 'w' line in status entry.");
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.wLine = sb.wLine + "\n" + sb.wLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    cb.buildConsensus();
  }

  @Test
  public void testWLineUnmeasured() throws DescriptorParseException {
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.wLine = "w Bandwidth=42424242 Unmeasured=1";
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    RelayNetworkStatusConsensus consensus = cb.buildConsensus();
    for (NetworkStatusEntry s : consensus.getStatusEntries().values()) {
      if (s.getBandwidth() == 42424242L) {
        assertTrue(s.getUnmeasured());
      }
    }
  }

  @Test
  public void testWLineNotUnmeasured() throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        StatusEntryBuilder.createWithWLine("w Bandwidth=20");
    for (NetworkStatusEntry s : consensus.getStatusEntries().values()) {
      assertFalse(s.getUnmeasured());
    }
  }

  @Test
  public void testPLineNoPolicy() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'p 80'.");
    StatusEntryBuilder.createWithPLine("p 80");
  }

  @Test
  public void testPLineNoPorts() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'p accept'.");
    StatusEntryBuilder.createWithPLine("p accept");
  }

  @Test
  public void testPLineNoPolicyNoPorts() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'p '.");
    StatusEntryBuilder.createWithPLine("p ");
  }

  @Test
  public void testPLineProject() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'p project 80'.");
    StatusEntryBuilder.createWithPLine("p project 80");
  }

  @Test
  public void testTwoPLines() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Duplicate 'p' line in status entry.");
    StatusEntryBuilder sb = new StatusEntryBuilder();
    sb.pLine = sb.pLine + "\n" + sb.pLine;
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.add(sb.buildStatusEntry());
    cb.buildConsensus();
  }

  @Test
  public void testNoStatusEntries() throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.statusEntries.clear();
    RelayNetworkStatusConsensus consensus = cb.buildConsensus();
    assertFalse(consensus.containsStatusEntry(
        "00795A6E8D91C270FC23B30F388A495553E01894"));
  }

  @Test
  public void testDirectoryFooterMissing()
      throws DescriptorParseException {
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.setDirectoryFooterLine(null);
    cb.setBandwidthWeightsLine(null);
    /* This does not break, because directory footers were optional before
     * consensus method 9. */
    RelayNetworkStatusConsensus consensus = cb.buildConsensus();
    assertNull(consensus.getBandwidthWeights());
  }

  @Test
  public void testDirectoryFooterLineSpace()
      throws DescriptorParseException {
    ConsensusBuilder.createWithDirectoryFooterLine("directory-footer ");
  }

  @Test
  public void testBandwidthWeightsNoLine()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus =
        ConsensusBuilder.createWithBandwidthWeightsLine(null);
    assertNull(consensus.getBandwidthWeights());
  }

  @Test
  public void testBandwidthWeightsLineNoSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithBandwidthWeightsLine("bandwidth-weights");
    assertNotNull(consensus.getBandwidthWeights());
  }

  @Test
  public void testBandwidthWeightsLineOneSpace()
      throws DescriptorParseException {
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithBandwidthWeightsLine("bandwidth-weights ");
    assertNotNull(consensus.getBandwidthWeights());
  }

  @Test
  public void testBandwidthWeightsLineNoEqualSign()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'bandwidth-weights Wbd-285' contains an "
        + "illegal value in list element 'Wbd-285'.");
    ConsensusBuilder.createWithBandwidthWeightsLine(
        "bandwidth-weights Wbd-285");
  }

  @Test
  public void testDirectorySignatureIdentityTooShort()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'directory-signature "
        + "ED03BB616EB2F60 845CF1D0B370CA443A8579D18E7987E7E532F639'.");
    DirectorySignatureBuilder.createWithIdentity("ED03BB616EB2F60");
  }

  @Test
  public void testDirectorySignatureIdentityTooLong()
      throws DescriptorParseException {
    /* This hex string has an unusual length of 58 hex characters, but
     * dir-spec.txt only requires a hex string, and we can't know all hex
     * string lengths for all future digest algorithms, so let's just
     * accept this. */
    DirectorySignatureBuilder.createWithIdentity(
        "ED03BB616EB2F60BEC80151114BB25CEF515B226ED03BB616EB2F60BEC");
  }

  @Test
  public void testDirectorySignatureSigningKeyTooShort()
      throws DescriptorParseException {
    /* See above, we accept this hex string even though it's unusually
     * short. */
    DirectorySignatureBuilder.createWithSigningKey("845CF1D0B370CA");
  }

  @Test
  public void testDirectorySignatureSigningKeyTooShortOddNumber()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'directory-signature "
        + "ED03BB616EB2F60BEC80151114BB25CEF515B226 845'.");
    /* We don't accept this hex string, because it contains an odd number
     * of hex characters. */
    DirectorySignatureBuilder.createWithSigningKey("845");
  }

  @Test
  public void testDirectorySignatureSigningKeyTooLong()
      throws DescriptorParseException {
    /* See above, we accept this hex string even though it's unusually
     * long. */
    DirectorySignatureBuilder.createWithSigningKey(
        "845CF1D0B370CA443A8579D18E7987E7E532F639845CF1D0B370CA443A");
  }

  @Test
  public void testNonAsciiByte20() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'network-status-version' must be "
        + "contained in the first line.");
    ConsensusBuilder cb = new ConsensusBuilder();
    byte[] consensusBytes = cb.buildConsensusBytes();
    consensusBytes[20] = (byte) 200;
    new RelayNetworkStatusConsensusImpl(consensusBytes,
        new int[] { 0, consensusBytes.length }, null);
  }

  @Test
  public void testNonAsciiByteMinusOne()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'network-status-version' "
        + "must be contained in the first line.");
    ConsensusBuilder cb = new ConsensusBuilder();
    cb.networkStatusVersionLine = "Xnetwork-status-version 3";
    byte[] consensusBytes = cb.buildConsensusBytes();
    consensusBytes[0] = (byte) 200;
    new RelayNetworkStatusConsensusImpl(consensusBytes,
        new int[] { 0, consensusBytes.length }, null);
  }

  @Test
  public void testUnrecognizedDirSourceLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithUnrecognizedDirSourceLine(unrecognizedLine);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }

  @Test
  public void testUnrecognizedStatusEntryLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithUnrecognizedStatusEntryLine(unrecognizedLine);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }

  @Test
  public void testUnrecognizedDirectoryFooterLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithUnrecognizedFooterLine(unrecognizedLine);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }

  @Test
  public void testUnrecognizedDirectorySignatureLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusConsensus consensus = ConsensusBuilder
        .createWithUnrecognizedDirectorySignatureLine(unrecognizedLine);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, consensus.getUnrecognizedLines());
  }
}

