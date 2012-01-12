/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.RelayNetworkStatusVote;
import org.torproject.descriptor.impl.RelayNetworkStatusVoteImpl;

import java.util.*;

import org.junit.*;
import org.junit.rules.*;
import static org.junit.Assert.*;

/* TODO Add test cases for all lines starting with "opt ". */

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
    private String dirSourceLine = "dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80";
    private static RelayNetworkStatusVote
        createWithDirSourceLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirSourceLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String contactLine = "contact 4096R/E012B42D Jacob Appelbaum "
        + "<jacob@appelbaum.net>";
    private static RelayNetworkStatusVote
        createWithContactLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.contactLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String dirKeyCertificateVersionLine =
        "dir-key-certificate-version 3";
    private static RelayNetworkStatusVote
        createWithDirKeyCertificateVersionLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyCertificateVersionLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String fingerprintLine = "fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C";
    private static RelayNetworkStatusVote
        createWithFingerprintLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.fingerprintLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String dirKeyPublishedLine = "dir-key-published 2011-04-27 "
        + "05:34:37";
    private static RelayNetworkStatusVote
        createWithDirKeyPublishedLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyPublishedLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String dirKeyExpiresLine = "dir-key-expires 2012-04-27 "
        + "05:34:37";
    private static RelayNetworkStatusVote
        createWithDirKeyExpiresLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyExpiresLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String dirIdentityKeyLines = "dir-identity-key\n"
        + "-----BEGIN RSA PUBLIC KEY-----\n"
        + "MIIBigKCAYEAtKpuLgVK25sfScjsxfVU1ljofrDygt9GP7bNJl/rghX42KUT97"
        + "5W\nrGp/fbhF7p+FcKCzNOhJFINQbRf/5E3lN8mzoamIU43QqQ9RRVf94688Us"
        + "azVsAN\nNVT0v9J0cr387WePjenRuIE1MmiP0nmw/XdvbPTayqax7VYlcUMXGH"
        + "l8DnWix1EN\nRwmeig+JBte0JS12oo2HG9zcSfjLJVjY6ZmvRrVycXiRxGc/Jg"
        + "NlSrV4cxUNykaB\nJ6pO6J499OZfQu7m1vAPTENrVJ4yEfRGRwFIY+d/s8BkKc"
        + "aiWtXAfTe31uBI6GEH\nmS3HNu1JVSuoaUiQIvVYDLMfBvMcNyAx97UT1l6E0T"
        + "n6a7pgChrquGwXai1xGzk8\n58aXwdSFoFBSTCkyemopq5H20p/nkPAO0pHL1k"
        + "TvcaKz9CEj4XcKm+kOmzejYmIa\nkbWNcRpXPiUZ+xmwGtsq30xrzqiONmERkx"
        + "qlmf7bVQPFvh3Kz6hGcmTBhTbHSe9h\nzDgmdaTNn3EHAgMBAAE=\n"
        + "-----END RSA PUBLIC KEY-----";
    private static RelayNetworkStatusVote
        createWithDirIdentityKeyLines(String lines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirIdentityKeyLines = lines;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String dirSigningKeyLines = "dir-signing-key\n"
        + "-----BEGIN RSA PUBLIC KEY-----\n"
        + "MIGJAoGBAN05qyHFQlTqykMP8yLuD4G2UuYulD4Xs8iSX5uqF+WGsUA1E4zZh4"
        + "8h\nDFj8+drFiCu3EqhMEmVG4ACtJK2uz6D1XohUsbPWTR6LSnWJ8q6/zfTSLu"
        + "mBGsN7\nPUXyMNjwRKL6UvrcbYk1d2mRBLO7SAP/sFW5fHhIBVeLIWrzQ19rAg"
        + "MBAAE=\n"
        + "-----END RSA PUBLIC KEY-----";
    private static RelayNetworkStatusVote
        createWithDirSigningKeyLines(String lines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirSigningKeyLines = lines;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String dirKeyCrosscertLines = "dir-key-crosscert\n"
        + "-----BEGIN ID SIGNATURE-----\n"
        + "rPBFn6IJ6TvAHj4pSwlg+RTn1fP89JGSVa08wuyJr5dAvZsdakQXvRjamT9oJU"
        + "aZ\nnY5Rl/tRlGuSQ0BglTPPKoXdKERK0FUr9f0EKrQy7NDUgE2j9losiRuyKz"
        + "hA3neZ\nK4yF8bhqAwM51u7fzAhIjNeRif9c04rhFJJCseco84w=\n"
        + "-----END ID SIGNATURE-----";
    private static RelayNetworkStatusVote
        createWithDirKeyCrosscertLines(String lines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyCrosscertLines = lines;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String dirKeyCertificationLines = "dir-key-certification\n"
        + "-----BEGIN SIGNATURE-----\n"
        + "hPSh6FuohNF5ccjiMbkvr8cZJwGFuL11cNtwN9k0X3pUdFZVATIEkqBe7z+rE2"
        + "PX\nPw+BGyC6wYAieoTVIhLpwKqd7DXLYjuhPZ28+7MQaDL01AqYeRp5PT01Px"
        + "rFY0Um\nlVf95uqUitgvDT76Ne4ExWk6UvGlYB9OBgBySZz8VWe9znoMqb0uHn"
        + "/p8IzqTApT\nAxRWXBHClntMeRqtGxaj8DcdJFn8yMxQiZG7MfDg2sq2ySPJyG"
        + "lN+neoVDVhZiDI\n9LTNmw60gWlUp2erFeam8Mo1ZBC4DPNjQEm6QeHZFZMkhD"
        + "uO6SwS/FL712A42+Co\nYtMaVot/p5FG2ZSBXbgl2XP5/z8ELnpmXqMbPAoWRo"
        + "3BPNSJkIQQNog8Q5ZrK+av\nZDw5eGPltGKsXOkvuzIMM8nBeAnDPDgYvzrIFO"
        + "bEGbvY/P8mzVAZxp3Yz+sRtNel\nC1SWz/Fx+Saex5oI7DJ3xtSD4XqKb/wYwZ"
        + "FT8IxDYq1t2tFXdHxd4QPRVcvc0zYC\n"
        + "-----END SIGNATURE-----";
    private static RelayNetworkStatusVote
        createWithDirKeyCertificationLines(String lines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyCertificationLines = lines;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private List<String> statusEntries = new ArrayList<String>();
    private String directoryFooterLine = "directory-footer";
    private static RelayNetworkStatusVote
        createWithDirectoryFooterLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.directoryFooterLine = line;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private String directorySignatureLines = "directory-signature "
          + "80550987E1D626E3EBA5E5E75A458DE0626D088C "
          + "EEB9299D295C1C815E289FBF2F2BBEA5F52FDD19\n"
          + "-----BEGIN SIGNATURE-----\n"
          + "iHEU3Iidya5RIrjyYgv8tlU0R+rF56/3/MmaaZi0a67e7ZkISfQ4dghScHxn"
          + "F3Yh\nrXVaaoP07r6Ta+s0g1Zijm3lms50Nk/4tV2p8Y63c3F4Q3DAnK40Oi"
          + "kfOIwEj+Ny\n+zBRQssP3hPhTPOj/A7o3mZZwtL6x1sxpeu/nME1l5E=\n"
          + "-----END SIGNATURE-----";
    private static RelayNetworkStatusVote
        createWithDirectorySignatureLines(String lines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.directorySignatureLines = lines;
      return new RelayNetworkStatusVoteImpl(vb.buildVote());
    }
    private VoteBuilder() {
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
      if (this.dirSourceLine != null) {
        sb.append(this.dirSourceLine + "\n");
      }
      if (this.contactLine != null) {
        sb.append(this.contactLine + "\n");
      }
      if (this.dirKeyCertificateVersionLine != null) {
        sb.append(this.dirKeyCertificateVersionLine + "\n");
      }
      if (this.fingerprintLine != null) {
        sb.append(this.fingerprintLine + "\n");
      }
      if (this.dirKeyPublishedLine != null) {
        sb.append(this.dirKeyPublishedLine + "\n");
      }
      if (this.dirKeyExpiresLine != null) {
        sb.append(this.dirKeyExpiresLine + "\n");
      }
      if (this.dirIdentityKeyLines != null) {
        sb.append(this.dirIdentityKeyLines + "\n");
      }
      if (this.dirSigningKeyLines != null) {
        sb.append(this.dirSigningKeyLines + "\n");
      }
      if (this.dirKeyCrosscertLines != null) {
        sb.append(this.dirKeyCrosscertLines + "\n");
      }
      if (this.dirKeyCertificationLines != null) {
        sb.append(this.dirKeyCertificationLines + "\n");
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
      if (this.directorySignatureLines != null) {
        sb.append(directorySignatureLines + "\n");
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

  @Test(expected = DescriptorParseException.class)
  public void testNicknameMissing() throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source  "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNicknameTooLong() throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source "
        + "urrassssssssssssssssssssssssssssssssssssssssssssssss "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testNicknameIllegalCharacters()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urra$ "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test()
  public void testFingerprintLowerCase() throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987e1d626e3eba5e5e75a458de0626d088c 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintTooShort() throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintTooLong() throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C8055 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintIllegalCharacters()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "ABCDEFGHIJKLM6E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + " 208.83.223.34 208.83.223.34 443 80");
  }

  @Test()
  public void testHostname256()
      throws DescriptorParseException {
    /* This test doesn't fail, because we're not parsing the hostname. */
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 256.256.256.256 "
        + "208.83.223.34 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testHostnameMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C  208.83.223.34 443 "
        + "80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddress256()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "256.256.256.256 443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testAddressMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34  443 "
        + "80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirPortMinus443()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 -443 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirPortFourFourThree()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 four-four-three 80");
  }

  @Test()
  public void testDirPort0() throws DescriptorParseException {
    /* This test doesn't fail, because we're accepting DirPort 0, even
     * though it doesn't make sense from Tor's view. */
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 0 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testOrPortMissing() throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 ");
  }

  @Test()
  public void testDirPortOrPortIdentical()
      throws DescriptorParseException {
    /* This test doesn't fail, even though identical OR and Dir port don't
     * make much sense from Tor's view. */
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 80 80");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceLineMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSourceLineDuplicate()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80\ndir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test()
  public void testContactLineMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithContactLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testContactLineDuplicate()
      throws DescriptorParseException {
    VoteBuilder.createWithContactLine("contact 4096R/E012B42D Jacob "
        + "Appelbaum <jacob@appelbaum.net>\ncontact 4096R/E012B42D Jacob "
        + "Appelbaum <jacob@appelbaum.net>");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyCertificateVersionLineMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyCertificateVersionLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyCertificateVersionLineDuplicate()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyCertificateVersionLine(
        "dir-key-certificate-version 3\ndir-key-certificate-version 3");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintLineMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithFingerprintLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintLineDuplicate()
      throws DescriptorParseException {
    VoteBuilder.createWithFingerprintLine("fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C\nfingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintLineTooLong()
      throws DescriptorParseException {
    VoteBuilder.createWithFingerprintLine("fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C8055");
  }

  @Test(expected = DescriptorParseException.class)
  public void testFingerprintLineTooShort()
      throws DescriptorParseException {
    VoteBuilder.createWithFingerprintLine("fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyPublished3011()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyPublishedLine("dir-key-published "
        + "3011-04-27 05:34:37");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyPublishedRecentlyAtNoon()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyPublishedLine("dir-key-published "
        + "recently 12:00:00");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyPublishedRecentlyNoTime()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyPublishedLine("dir-key-published "
        + "recently");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyExpiresSoonAtNoon()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyExpiresLine("dir-key-expires "
        + "soon 12:00:00");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyExpiresLineMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyExpiresLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyExpiresLineDuplicate()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyExpiresLine("dir-key-expires 2012-04-27 "
        + "05:34:37\ndir-key-expires 2012-04-27 05:34:37");
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirIdentityKeyLinesMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirIdentityKeyLines(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirSigningKeyLinesMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirSigningKeyLines(null);
  }

  @Test()
  public void testDirKeyCrosscertLinesMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyCrosscertLines(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirKeyCertificationLinesMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyCertificationLines(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirectoryFooterLineMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirectoryFooterLine(null);
  }

  @Test(expected = DescriptorParseException.class)
  public void testDirectorySignaturesLinesMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirectorySignatureLines(null);
  }
}

