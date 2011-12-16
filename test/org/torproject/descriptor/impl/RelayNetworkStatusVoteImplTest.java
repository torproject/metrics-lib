/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.RelayNetworkStatusVote;
import org.torproject.descriptor.impl.RelayNetworkStatusVoteImpl;

import java.util.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

/* TODO Add tests (and possibly a DirSourceLineBuilder) to test the
 * following methods:
 * - String getNickname();
 * - String getIdentity();
 * - String getAddress();
 * - int getDirport();
 * - int getOrport();
 * - String getContactLine();
 * - int getDirKeyCertificateVersion();
 * - String getLegacyKey();
 * - long getDirKeyPublishedMillis();
 * - long getDirKeyExpiresMillis();
 * - String getSigningKeyDigest();
 */

/* Test parsing of network status votes.  Some of the vote-parsing code is
 * already tested in the consensus-parsing tests.  The tests in this class
 * focus on the differences between votes and consensuses that are mostly
 * in the directory header. */
public class RelayNetworkStatusVoteImplTest {

  /* Helper class to build a vote based on default data and modifications
   * requested by test methods. */
  private static class VoteBuilder {
    private String networkStatusVersionLine = "network-status-version 3";
    private static RelayNetworkStatusVote
        createWithNetworkStatusVersionLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.networkStatusVersionLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String voteStatusLine = "vote-status vote";
    private static RelayNetworkStatusVote
        createWithVoteStatusLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.voteStatusLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String consensusMethodsLine =
        "consensus-methods 1 2 3 4 5 6 7 8 9 10 11";
    private static RelayNetworkStatusVote
        createWithConsensusMethodsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.consensusMethodsLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String publishedLine = "published 2011-11-30 08:50:01";
    private static RelayNetworkStatusVote
        createWithPublishedLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.publishedLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String validAfterLine = "valid-after 2011-11-30 09:00:00";
    private static RelayNetworkStatusVote
        createWithValidAfterLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.validAfterLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String freshUntilLine = "fresh-until 2011-11-30 10:00:00";
    private static RelayNetworkStatusVote
        createWithFreshUntilLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.freshUntilLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String validUntilLine = "valid-until 2011-11-30 12:00:00";
    private static RelayNetworkStatusVote
        createWithValidUntilLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.validUntilLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String votingDelayLine = "voting-delay 300 300";
    private static RelayNetworkStatusVote
        createWithVotingDelayLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.votingDelayLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String clientVersionsLine = "client-versions 0.2.1.31,"
        + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";
    private static RelayNetworkStatusVote
        createWithClientVersionsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.clientVersionsLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String serverVersionsLine = "server-versions 0.2.1.31,"
        + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";
    private static RelayNetworkStatusVote
        createWithServerVersionsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.serverVersionsLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String knownFlagsLine = "known-flags Authority BadExit Exit "
        + "Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid";
    private static RelayNetworkStatusVote
        createWithKnownFlagsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.knownFlagsLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String paramsLine = "params "
        + "CircuitPriorityHalflifeMsec=30000 bwauthbestratio=1 "
        + "bwauthcircs=1 bwauthdescbw=0 bwauthkp=10000 bwauthpid=1 "
        + "bwauthtd=5000 bwauthti=50000 bwauthtidecay=5000 cbtnummodes=3 "
        + "cbtquantile=80 circwindow=1000 refuseunknownexits=1";
    private static RelayNetworkStatusVote
        createWithParamsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.paramsLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private List<String> dirSources = new ArrayList<String>();
    private List<String> statusEntries = new ArrayList<String>();
    private String directoryFooterLine = "directory-footer";
    private static RelayNetworkStatusVote
        createWithDirectoryFooterLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.directoryFooterLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private List<String> directorySignatures = new ArrayList<String>();
    private VoteBuilder() {
      this.dirSources.add("dir-source urras "
          + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
          + "208.83.223.34 443 80\n"
          + "contact 4096R/E012B42D Jacob Appelbaum "
          + "<jacob@appelbaum.net>\n"
          + "dir-key-certificate-version 3\n"
          + "fingerprint 80550987E1D626E3EBA5E5E75A458DE0626D088C\n"
          + "dir-key-published 2011-04-27 05:34:37\n"
          + "dir-key-expires 2012-04-27 05:34:37\n"
          + "dir-identity-key\n"
          + "-----BEGIN RSA PUBLIC KEY-----\n"
          + "MIIBigKCAYEAtKpuLgVK25sfScjsxfVU1ljofrDygt9GP7bNJl/rghX42KUT"
          + "975W\nrGp/fbhF7p+FcKCzNOhJFINQbRf/5E3lN8mzoamIU43QqQ9RRVf946"
          + "88UsazVsAN\nNVT0v9J0cr387WePjenRuIE1MmiP0nmw/XdvbPTayqax7VYl"
          + "cUMXGHl8DnWix1EN\nRwmeig+JBte0JS12oo2HG9zcSfjLJVjY6ZmvRrVycX"
          + "iRxGc/JgNlSrV4cxUNykaB\nJ6pO6J499OZfQu7m1vAPTENrVJ4yEfRGRwFI"
          + "Y+d/s8BkKcaiWtXAfTe31uBI6GEH\nmS3HNu1JVSuoaUiQIvVYDLMfBvMcNy"
          + "Ax97UT1l6E0Tn6a7pgChrquGwXai1xGzk8\n58aXwdSFoFBSTCkyemopq5H2"
          + "0p/nkPAO0pHL1kTvcaKz9CEj4XcKm+kOmzejYmIa\nkbWNcRpXPiUZ+xmwGt"
          + "sq30xrzqiONmERkxqlmf7bVQPFvh3Kz6hGcmTBhTbHSe9h\nzDgmdaTNn3EH"
          + "AgMBAAE=\n"
          + "-----END RSA PUBLIC KEY-----\n"
          + "dir-signing-key\n"
          + "-----BEGIN RSA PUBLIC KEY-----\n"
          + "MIGJAoGBAN05qyHFQlTqykMP8yLuD4G2UuYulD4Xs8iSX5uqF+WGsUA1E4zZ"
          + "h48h\nDFj8+drFiCu3EqhMEmVG4ACtJK2uz6D1XohUsbPWTR6LSnWJ8q6/zf"
          + "TSLumBGsN7\nPUXyMNjwRKL6UvrcbYk1d2mRBLO7SAP/sFW5fHhIBVeLIWrz"
          + "Q19rAgMBAAE=\n"
          + "-----END RSA PUBLIC KEY-----\n"
          + "dir-key-crosscert\n"
          + "-----BEGIN ID SIGNATURE-----\n"
          + "rPBFn6IJ6TvAHj4pSwlg+RTn1fP89JGSVa08wuyJr5dAvZsdakQXvRjamT9o"
          + "JUaZ\nnY5Rl/tRlGuSQ0BglTPPKoXdKERK0FUr9f0EKrQy7NDUgE2j9losiR"
          + "uyKzhA3neZ\nK4yF8bhqAwM51u7fzAhIjNeRif9c04rhFJJCseco84w=\n"
          + "-----END ID SIGNATURE-----\n"
          + "dir-key-certification\n"
          + "-----BEGIN SIGNATURE-----\n"
          + "hPSh6FuohNF5ccjiMbkvr8cZJwGFuL11cNtwN9k0X3pUdFZVATIEkqBe7z+r"
          + "E2PX\nPw+BGyC6wYAieoTVIhLpwKqd7DXLYjuhPZ28+7MQaDL01AqYeRp5PT"
          + "01PxrFY0Um\nlVf95uqUitgvDT76Ne4ExWk6UvGlYB9OBgBySZz8VWe9znoM"
          + "qb0uHn/p8IzqTApT\nAxRWXBHClntMeRqtGxaj8DcdJFn8yMxQiZG7MfDg2s"
          + "q2ySPJyGlN+neoVDVhZiDI\n9LTNmw60gWlUp2erFeam8Mo1ZBC4DPNjQEm6"
          + "QeHZFZMkhDuO6SwS/FL712A42+Co\nYtMaVot/p5FG2ZSBXbgl2XP5/z8ELn"
          + "pmXqMbPAoWRo3BPNSJkIQQNog8Q5ZrK+av\nZDw5eGPltGKsXOkvuzIMM8nB"
          + "eAnDPDgYvzrIFObEGbvY/P8mzVAZxp3Yz+sRtNel\nC1SWz/Fx+Saex5oI7D"
          + "J3xtSD4XqKb/wYwZFT8IxDYq1t2tFXdHxd4QPRVcvc0zYC\n"
          + "-----END SIGNATURE-----");
      this.statusEntries.add("r right2privassy3 "
          + "ADQ6gCT3DiFHKPDFr3rODBUI8HM lJY5Vf7kXec+VdkGW2flEsfkFC8 "
          + "2011-11-12 00:03:40 50.63.8.215 9023 0\n"
          + "s Exit Fast Guard Running Stable Valid\n"
          + "opt v Tor 0.2.1.29 (r8e9b25e6c7a2e70c)\n"
          + "w Bandwidth=297 Measured=73\n"
          + "p accept 80,1194,1220,1293,1500,1533,1677,1723,1863,"
          + "2082-2083,2086-2087,2095-2096,2102-2104,3128,3389,3690,4321,"
          + "4643,5050,5190,5222-5223,5228,5900,6660-6669,6679,6697,8000,"
          + "8008,8074,8080,8087-8088,8443,8888,9418,9999-10000,19294,"
          + "19638\n"
          + "m 8,9,10,11 "
          + "sha256=9ciEx9t0McXk9A06I7qwN7pxuNOdpCP64RV/6cx2Zkc");
      this.directorySignatures.add("directory-signature "
          + "80550987E1D626E3EBA5E5E75A458DE0626D088C "
          + "EEB9299D295C1C815E289FBF2F2BBEA5F52FDD19\n"
          + "-----BEGIN SIGNATURE-----\n"
          + "iHEU3Iidya5RIrjyYgv8tlU0R+rF56/3/MmaaZi0a67e7ZkISfQ4dghScHxn"
          + "F3Yh\nrXVaaoP07r6Ta+s0g1Zijm3lms50Nk/4tV2p8Y63c3F4Q3DAnK40Oi"
          + "kfOIwEj+Ny\n+zBRQssP3hPhTPOj/A7o3mZZwtL6x1sxpeu/nME1l5E=\n"
          + "-----END SIGNATURE-----");
    }
    private byte[] buildVote() {
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
      if (this.consensusMethodsLine != null) {
        sb.append(this.consensusMethodsLine + "\n");
      }
      if (this.publishedLine != null) {
        sb.append(this.publishedLine + "\n");
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
      for (String directorySignature : this.directorySignatures) {
        sb.append(directorySignature + "\n");
      }
    }
  }

  @Test()
  public void testSampleVote() throws DescriptorParseException {
    VoteBuilder vb = new VoteBuilder();
    RelayNetworkStatusVote vote =
        new RelayNetworkStatusVoteImpl(vb.buildVote());
    assertEquals(3, vote.getNetworkStatusVersion());
    List<Integer> consensusMethods = Arrays.asList(
        new Integer[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11});
    assertEquals(vote.getConsensusMethods(), consensusMethods);
    assertEquals(1322643001000L, vote.getPublishedMillis());
    assertEquals(1322643600000L, vote.getValidAfterMillis());
    assertEquals(1322647200000L, vote.getFreshUntilMillis());
    assertEquals(1322654400000L, vote.getValidUntilMillis());
    assertEquals(300L, vote.getVoteSeconds());
    assertEquals(300L, vote.getDistSeconds());
    assertTrue(vote.getKnownFlags().contains("Running"));
    assertEquals(30000, (int) vote.getConsensusParams().get(
        "CircuitPriorityHalflifeMsec"));
    assertEquals("Tor 0.2.1.29 (r8e9b25e6c7a2e70c)",
        vote.getStatusEntry("00343A8024F70E214728F0C5AF7ACE0C1508F073").
        getVersion());
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNoLine()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNewLine()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNewLineSpace()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionPrefixLineAtChar()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "@vote\nnetwork-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionPrefixLine()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "directory-footer\nnetwork-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionPrefixLinePoundChar()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "#vote\nnetwork-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionNoSpace()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionOneSpace()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersion42()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 42");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionFourtyTwo()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version FourtyTwo");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusNoLine() throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testNetworkStatusVersionSpaceBefore()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        " network-status-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusSpaceBefore() throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine(" vote-status vote");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusNoSpace() throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine("vote-status");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusOneSpace() throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine("vote-status ");
  }

  @Test()
  public void testVoteStatusVoteOneSpace()
      throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine("vote-status vote ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusConsensus() throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine("vote-status consensus");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVoteStatusTheMagicVoteStatus()
      throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine(
        "vote-status TheMagicVoteStatus");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodNoLine()
      throws DescriptorParseException {
    VoteBuilder.createWithConsensusMethodsLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodNoSpace()
      throws DescriptorParseException {
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodOneSpace()
      throws DescriptorParseException {
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodEleven()
      throws DescriptorParseException {
    VoteBuilder.createWithConsensusMethodsLine(
        "consensus-methods eleven");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodMinusOne()
      throws DescriptorParseException {
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods -1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodNinePeriod()
      throws DescriptorParseException {
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods "
        + "999999999999999999999999999999999999999999999999999999999999");
  }

  @Test(expected = DescriptorParseException.class)
  public void testConsensusMethodTwoLines()
      throws DescriptorParseException {
    VoteBuilder.createWithConsensusMethodsLine(
        "consensus-method 1\nconsensus-method 1");
  }

  @Test(expected = DescriptorParseException.class)
  public void testPublishedNoLine() throws DescriptorParseException {
    VoteBuilder.createWithPublishedLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterNoLine() throws DescriptorParseException {
    VoteBuilder.createWithValidAfterLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterNoSpace() throws DescriptorParseException {
    VoteBuilder.createWithValidAfterLine("valid-after");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterOneSpace() throws DescriptorParseException {
    VoteBuilder.createWithValidAfterLine("valid-after ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterLongAgo() throws DescriptorParseException {
    VoteBuilder.createWithValidAfterLine("valid-after long ago");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidAfterFeb30() throws DescriptorParseException {
    VoteBuilder.createWithValidAfterLine(
        "valid-after 2011-02-30 09:00:00");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFreshUntilNoLine() throws DescriptorParseException {
    VoteBuilder.createWithFreshUntilLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testFreshUntilAroundTen() throws DescriptorParseException {
    VoteBuilder.createWithFreshUntilLine(
        "fresh-until 2011-11-30 around ten");
  }

  @Test(expected = DescriptorParseException.class)
  public void testValidUntilTomorrowMorning()
      throws DescriptorParseException {
    VoteBuilder.createWithValidUntilLine(
        "valid-until tomorrow morning");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayNoLine() throws DescriptorParseException {
    VoteBuilder.createWithVotingDelayLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayNoSpace() throws DescriptorParseException {
    VoteBuilder.createWithVotingDelayLine("voting-delay");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayOneSpace() throws DescriptorParseException {
    VoteBuilder.createWithVotingDelayLine("voting-delay ");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayTriple() throws DescriptorParseException {
    VoteBuilder.createWithVotingDelayLine(
        "voting-delay 300 300 300");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelaySingle() throws DescriptorParseException {
    VoteBuilder.createWithVotingDelayLine("voting-delay 300");
  }

  @Test(expected = DescriptorParseException.class)
  public void testVotingDelayOneTwo() throws DescriptorParseException {
    VoteBuilder.createWithVotingDelayLine("voting-delay one two");
  }

  @Test(expected = DescriptorParseException.class)
  public void testClientVersionsComma() throws DescriptorParseException {
    VoteBuilder.createWithClientVersionsLine("client-versions ,");
  }

  @Test(expected = DescriptorParseException.class)
  public void testClientVersionsCommaVersion()
      throws DescriptorParseException {
    VoteBuilder.createWithClientVersionsLine(
        "client-versions ,0.2.2.34");
  }

  @Test(expected = DescriptorParseException.class)
  public void testKnownFlagsNoLine() throws DescriptorParseException {
    VoteBuilder.createWithKnownFlagsLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testKnownFlagsNoSpace() throws DescriptorParseException {
    VoteBuilder.createWithKnownFlagsLine("known-flags");
  }

  @Test(expected = DescriptorParseException.class)
  public void testKnownFlagsOneSpace() throws DescriptorParseException {
    VoteBuilder.createWithKnownFlagsLine("known-flags ");
  }
}

