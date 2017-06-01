/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DirectorySignature;
import org.torproject.descriptor.RelayNetworkStatusVote;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.TreeSet;

/* TODO Add test cases for all lines starting with "opt ". */

/* Test parsing of network status votes.  Some of the vote-parsing code is
 * already tested in the consensus-parsing tests.  The tests in this class
 * focus on the differences between votes and consensuses that are mostly
 * in the directory header. */
public class RelayNetworkStatusVoteImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  /* Helper class to build a vote based on default data and modifications
   * requested by test methods. */
  private static class VoteBuilder {

    private String networkStatusVersionLine = "network-status-version 3";

    private static RelayNetworkStatusVote
        createWithNetworkStatusVersionLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.networkStatusVersionLine = line;
      return vb.buildVote(true);
    }

    private String voteStatusLine = "vote-status vote";

    private static RelayNetworkStatusVote
        createWithVoteStatusLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.voteStatusLine = line;
      return vb.buildVote(true);
    }

    private String consensusMethodsLine =
        "consensus-methods 1 2 3 4 5 6 7 8 9 10 11";

    private static RelayNetworkStatusVote
        createWithConsensusMethodsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.consensusMethodsLine = line;
      return vb.buildVote(true);
    }

    private String publishedLine = "published 2011-11-30 08:50:01";

    private static RelayNetworkStatusVote
        createWithPublishedLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.publishedLine = line;
      return vb.buildVote(true);
    }

    private String validAfterLine = "valid-after 2011-11-30 09:00:00";

    private static RelayNetworkStatusVote
        createWithValidAfterLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.validAfterLine = line;
      return vb.buildVote(true);
    }

    private String freshUntilLine = "fresh-until 2011-11-30 10:00:00";

    private static RelayNetworkStatusVote
        createWithFreshUntilLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.freshUntilLine = line;
      return vb.buildVote(true);
    }

    private String validUntilLine = "valid-until 2011-11-30 12:00:00";

    private static RelayNetworkStatusVote
        createWithValidUntilLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.validUntilLine = line;
      return vb.buildVote(true);
    }

    private String votingDelayLine = "voting-delay 300 300";

    private static RelayNetworkStatusVote
        createWithVotingDelayLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.votingDelayLine = line;
      return vb.buildVote(true);
    }

    private String clientVersionsLine = "client-versions 0.2.1.31,"
        + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";

    private static RelayNetworkStatusVote
        createWithClientVersionsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.clientVersionsLine = line;
      return vb.buildVote(true);
    }

    private String serverVersionsLine = "server-versions 0.2.1.31,"
        + "0.2.2.34,0.2.3.6-alpha,0.2.3.7-alpha,0.2.3.8-alpha";

    private static RelayNetworkStatusVote
        createWithServerVersionsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.serverVersionsLine = line;
      return vb.buildVote(true);
    }

    private String packageLines = null;

    protected static RelayNetworkStatusVote
        createWithPackageLines(String lines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.packageLines = lines;
      return vb.buildVote(true);
    }

    private String knownFlagsLine = "known-flags Authority BadExit Exit "
        + "Fast Guard HSDir Named Running Stable Unnamed V2Dir Valid";

    private static RelayNetworkStatusVote
        createWithKnownFlagsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.knownFlagsLine = line;
      return vb.buildVote(true);
    }

    private String recommendedClientProtocolsLine =
        "recommended-client-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 "
        + "HSIntro=3 HSRend=1 Link=4 LinkAuth=1 Microdesc=1-2 Relay=2";

    private static RelayNetworkStatusVote
        createWithRecommendedClientProtocolsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.recommendedClientProtocolsLine = line;
      return vb.buildVote(true);
    }

    private String recommendedRelayProtocolsLine =
        "recommended-relay-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 "
        + "HSIntro=3 HSRend=1 Link=4 LinkAuth=1 Microdesc=1-2 Relay=2";

    private static RelayNetworkStatusVote
        createWithRecommendedRelayProtocolsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.recommendedRelayProtocolsLine = line;
      return vb.buildVote(true);
    }

    private String requiredClientProtocolsLine =
        "required-client-protocols Cons=1-2 Desc=1-2 DirCache=1 HSDir=1 "
        + "HSIntro=3 HSRend=1 Link=4 LinkAuth=1 Microdesc=1-2 Relay=2";

    private static RelayNetworkStatusVote
        createWithRequiredClientProtocolsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.requiredClientProtocolsLine = line;
      return vb.buildVote(true);
    }

    private String requiredRelayProtocolsLine =
        "required-relay-protocols Cons=1 Desc=1 DirCache=1 HSDir=1 HSIntro=3 "
        + "HSRend=1 Link=3-4 LinkAuth=1 Microdesc=1 Relay=1-2";

    private static RelayNetworkStatusVote
        createWithRequiredRelayProtocolsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.requiredRelayProtocolsLine = line;
      return vb.buildVote(true);
    }

    private String flagThresholdsLine = "flag-thresholds "
        + "stable-uptime=693369 stable-mtbf=153249 fast-speed=40960 "
        + "guard-wfu=94.669% guard-tk=691200 guard-bw-inc-exits=174080 "
        + "guard-bw-exc-exits=184320 enough-mtbf=1";

    private static RelayNetworkStatusVote
        createWithFlagThresholdsLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.flagThresholdsLine = line;
      return vb.buildVote(true);
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
      return vb.buildVote(true);
    }

    private String dirSourceLine = "dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80";

    private static RelayNetworkStatusVote
        createWithDirSourceLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirSourceLine = line;
      return vb.buildVote(true);
    }

    private String contactLine = "contact 4096R/E012B42D Jacob Appelbaum "
        + "<jacob@appelbaum.net>";

    private static RelayNetworkStatusVote
        createWithContactLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.contactLine = line;
      return vb.buildVote(true);
    }

    private String sharedRandParticipateLine = "shared-rand-participate";

    private static RelayNetworkStatusVote createWithSharedRandParticipateLine(
        String line) throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.sharedRandParticipateLine = line;
      return vb.buildVote(true);
    }

    private List<String> sharedRandCommitLines = Arrays.asList(new String[] {
        "shared-rand-commit 1 sha3-256 "
        + "0232AF901C31A04EE9848595AF9BB7620D4C5B2E "
        + "AAAAAFieVABh3Aauk2h31FVKaW0xIm28T7VPDkzP5nHwoMItxp7iQg==",
        "shared-rand-commit 1 sha3-256 "
        + "14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 "
        + "AAAAAFieVAA26LuAu9z2UhalmV7zuczWauSkqp1c/bsPA3AkH85iGw==" });

    private static RelayNetworkStatusVote createWithSharedRandCommitLines(
        List<String> lines) throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.sharedRandCommitLines = lines;
      return vb.buildVote(true);
    }

    private String sharedRandPreviousValueLine =
        "shared-rand-previous-value 8 "
        + "grwbnD6I40odtsdtWYxqs0DvPweCur6qG2Fo5p5ivS4=";

    private static RelayNetworkStatusVote createWithSharedRandPreviousValueLine(
        String line) throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.sharedRandPreviousValueLine = line;
      return vb.buildVote(true);
    }

    private String sharedRandCurrentValueLine =
        "shared-rand-current-value 8 "
        + "D88plxd8YeLfCIVAR9gjiFlWB1WqpC53kWr350o1pzw=";

    private static RelayNetworkStatusVote createWithSharedRandCurrentValueLine(
        String line) throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.sharedRandCurrentValueLine = line;
      return vb.buildVote(true);
    }

    private String legacyDirKeyLine = null;

    private static RelayNetworkStatusVote
        createWithLegacyDirKeyLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.legacyDirKeyLine = line;
      return vb.buildVote(true);
    }

    private String dirKeyCertificateVersionLine =
        "dir-key-certificate-version 3";

    private static RelayNetworkStatusVote
        createWithDirKeyCertificateVersionLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyCertificateVersionLine = line;
      return vb.buildVote(true);
    }

    private String fingerprintLine = "fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C";

    private static RelayNetworkStatusVote
        createWithFingerprintLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.fingerprintLine = line;
      return vb.buildVote(true);
    }

    private String dirKeyPublishedLine = "dir-key-published 2011-04-27 "
        + "05:34:37";

    private static RelayNetworkStatusVote
        createWithDirKeyPublishedLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyPublishedLine = line;
      return vb.buildVote(true);
    }

    private String dirKeyExpiresLine = "dir-key-expires 2012-04-27 "
        + "05:34:37";

    private static RelayNetworkStatusVote
        createWithDirKeyExpiresLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.dirKeyExpiresLine = line;
      return vb.buildVote(true);
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
      return vb.buildVote(true);
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
      return vb.buildVote(true);
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
      return vb.buildVote(true);
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
      return vb.buildVote(true);
    }

    private List<String> statusEntries = null;

    private static RelayNetworkStatusVote createWithStatusEntries(
        List<String> statusEntries) throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.statusEntries = statusEntries;
      return vb.buildVote(true);
    }

    private String directoryFooterLine = "directory-footer";

    private static RelayNetworkStatusVote
        createWithDirectoryFooterLine(String line)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.directoryFooterLine = line;
      return vb.buildVote(true);
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
      return vb.buildVote(true);
    }

    private String unrecognizedHeaderLine = null;

    protected static RelayNetworkStatusVote
        createWithUnrecognizedHeaderLine(String line,
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.unrecognizedHeaderLine = line;
      return vb.buildVote(failUnrecognizedDescriptorLines);
    }

    private String unrecognizedDirSourceLine = null;

    protected static RelayNetworkStatusVote
        createWithUnrecognizedDirSourceLine(String line,
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.unrecognizedDirSourceLine = line;
      return vb.buildVote(failUnrecognizedDescriptorLines);
    }

    private String unrecognizedStatusEntryLine = null;

    protected static RelayNetworkStatusVote
        createWithUnrecognizedStatusEntryLine(String line,
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.unrecognizedStatusEntryLine = line;
      return vb.buildVote(failUnrecognizedDescriptorLines);
    }

    private String unrecognizedFooterLine = null;

    protected static RelayNetworkStatusVote
        createWithUnrecognizedFooterLine(String line,
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.unrecognizedFooterLine = line;
      return vb.buildVote(failUnrecognizedDescriptorLines);
    }

    private String unrecognizedDirectorySignatureLine = null;

    protected static RelayNetworkStatusVote
        createWithUnrecognizedDirectorySignatureLine(String line,
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      VoteBuilder vb = new VoteBuilder();
      vb.unrecognizedDirectorySignatureLine = line;
      return vb.buildVote(failUnrecognizedDescriptorLines);
    }

    private VoteBuilder() {
      if (this.statusEntries != null) {
        return;
      }
      this.statusEntries = new ArrayList<>();
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

    private byte[] buildVoteBytes() {
      StringBuilder sb = new StringBuilder();
      this.appendHeader(sb);
      this.appendDirSource(sb);
      this.appendStatusEntries(sb);
      this.appendFooter(sb);
      this.appendDirectorySignature(sb);
      return sb.toString().getBytes();
    }

    private RelayNetworkStatusVoteImpl buildVote(
        boolean failUnrecognizedDescriptorLines)
        throws DescriptorParseException {
      byte[] voteBytes = this.buildVoteBytes();
      return new RelayNetworkStatusVoteImpl(voteBytes,
          new int[] { 0, voteBytes.length }, failUnrecognizedDescriptorLines);
    }

    private void appendHeader(StringBuilder sb) {
      if (this.networkStatusVersionLine != null) {
        sb.append(this.networkStatusVersionLine).append("\n");
      }
      if (this.voteStatusLine != null) {
        sb.append(this.voteStatusLine).append("\n");
      }
      if (this.consensusMethodsLine != null) {
        sb.append(this.consensusMethodsLine).append("\n");
      }
      if (this.publishedLine != null) {
        sb.append(this.publishedLine).append("\n");
      }
      if (this.validAfterLine != null) {
        sb.append(this.validAfterLine).append("\n");
      }
      if (this.freshUntilLine != null) {
        sb.append(this.freshUntilLine).append("\n");
      }
      if (this.validUntilLine != null) {
        sb.append(this.validUntilLine).append("\n");
      }
      if (this.votingDelayLine != null) {
        sb.append(this.votingDelayLine).append("\n");
      }
      if (this.clientVersionsLine != null) {
        sb.append(this.clientVersionsLine).append("\n");
      }
      if (this.serverVersionsLine != null) {
        sb.append(this.serverVersionsLine).append("\n");
      }
      if (this.packageLines != null) {
        sb.append(this.packageLines).append("\n");
      }
      if (this.knownFlagsLine != null) {
        sb.append(this.knownFlagsLine).append("\n");
      }
      if (this.recommendedClientProtocolsLine != null) {
        sb.append(this.recommendedClientProtocolsLine).append("\n");
      }
      if (this.recommendedRelayProtocolsLine != null) {
        sb.append(this.recommendedRelayProtocolsLine).append("\n");
      }
      if (this.requiredClientProtocolsLine != null) {
        sb.append(this.requiredClientProtocolsLine).append("\n");
      }
      if (this.requiredRelayProtocolsLine != null) {
        sb.append(this.requiredRelayProtocolsLine).append("\n");
      }
      if (this.flagThresholdsLine != null) {
        sb.append(this.flagThresholdsLine).append("\n");
      }
      if (this.paramsLine != null) {
        sb.append(this.paramsLine).append("\n");
      }
      if (this.unrecognizedHeaderLine != null) {
        sb.append(this.unrecognizedHeaderLine).append("\n");
      }
    }

    private void appendDirSource(StringBuilder sb) {
      if (this.dirSourceLine != null) {
        sb.append(this.dirSourceLine).append("\n");
      }
      if (this.contactLine != null) {
        sb.append(this.contactLine).append("\n");
      }
      if (this.sharedRandParticipateLine != null) {
        sb.append(this.sharedRandParticipateLine).append("\n");
      }
      if (this.sharedRandCommitLines != null) {
        for (String line : this.sharedRandCommitLines) {
          sb.append(line).append("\n");
        }
      }
      if (this.sharedRandPreviousValueLine != null) {
        sb.append(this.sharedRandPreviousValueLine).append("\n");
      }
      if (this.sharedRandCurrentValueLine != null) {
        sb.append(this.sharedRandCurrentValueLine).append("\n");
      }
      if (this.legacyDirKeyLine != null) {
        sb.append(this.legacyDirKeyLine).append("\n");
      }
      if (this.dirKeyCertificateVersionLine != null) {
        sb.append(this.dirKeyCertificateVersionLine).append("\n");
      }
      if (this.fingerprintLine != null) {
        sb.append(this.fingerprintLine).append("\n");
      }
      if (this.dirKeyPublishedLine != null) {
        sb.append(this.dirKeyPublishedLine).append("\n");
      }
      if (this.dirKeyExpiresLine != null) {
        sb.append(this.dirKeyExpiresLine).append("\n");
      }
      if (this.dirIdentityKeyLines != null) {
        sb.append(this.dirIdentityKeyLines).append("\n");
      }
      if (this.dirSigningKeyLines != null) {
        sb.append(this.dirSigningKeyLines).append("\n");
      }
      if (this.dirKeyCrosscertLines != null) {
        sb.append(this.dirKeyCrosscertLines).append("\n");
      }
      if (this.dirKeyCertificationLines != null) {
        sb.append(this.dirKeyCertificationLines).append("\n");
      }
      if (this.unrecognizedDirSourceLine != null) {
        sb.append(this.unrecognizedDirSourceLine).append("\n");
      }
    }

    private void appendStatusEntries(StringBuilder sb) {
      for (String statusEntry : this.statusEntries) {
        sb.append(statusEntry).append("\n");
      }
      if (this.unrecognizedStatusEntryLine != null) {
        sb.append(this.unrecognizedStatusEntryLine).append("\n");
      }
    }

    private void appendFooter(StringBuilder sb) {
      if (this.directoryFooterLine != null) {
        sb.append(this.directoryFooterLine).append("\n");
      }
      if (this.unrecognizedFooterLine != null) {
        sb.append(this.unrecognizedFooterLine).append("\n");
      }
    }

    private void appendDirectorySignature(StringBuilder sb) {
      if (this.directorySignatureLines != null) {
        sb.append(directorySignatureLines).append("\n");
      }
      if (this.unrecognizedDirectorySignatureLine != null) {
        sb.append(this.unrecognizedDirectorySignatureLine).append("\n");
      }
    }
  }

  @Test()
  public void testSampleVote() throws DescriptorParseException {
    VoteBuilder vb = new VoteBuilder();
    RelayNetworkStatusVote vote = vb.buildVote(true);
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
        vote.getStatusEntry("00343A8024F70E214728F0C5AF7ACE0C1508F073")
        .getVersion());
    assertEquals(3, vote.getDirKeyCertificateVersion());
    assertEquals("80550987E1D626E3EBA5E5E75A458DE0626D088C",
        vote.getIdentity());
    assertEquals(1303882477000L, /* 2011-04-27 05:34:37 */
        vote.getDirKeyPublishedMillis());
    assertEquals(1335504877000L, /* 2012-04-27 05:34:37 */
        vote.getDirKeyExpiresMillis());
    assertEquals("-----BEGIN RSA PUBLIC KEY-----",
        vote.getDirIdentityKey().split("\n")[0]);
    assertEquals("-----BEGIN RSA PUBLIC KEY-----",
        vote.getDirSigningKey().split("\n")[0]);
    assertEquals("-----BEGIN ID SIGNATURE-----",
        vote.getDirKeyCrosscert().split("\n")[0]);
    assertEquals("-----BEGIN SIGNATURE-----",
        vote.getDirKeyCertification().split("\n")[0]);
    assertEquals(1, vote.getSignatures().size());
    DirectorySignature signature = vote.getSignatures().get(0);
    assertEquals("sha1", signature.getAlgorithm());
    assertEquals("80550987E1D626E3EBA5E5E75A458DE0626D088C",
        signature.getIdentity());
    assertEquals("EEB9299D295C1C815E289FBF2F2BBEA5F52FDD19",
        signature.getSigningKeyDigestSha1Hex());
    assertEquals("-----BEGIN SIGNATURE-----\n"
        + "iHEU3Iidya5RIrjyYgv8tlU0R+rF56/3/MmaaZi0a67e7ZkISfQ4dghScHxn"
        + "F3Yh\nrXVaaoP07r6Ta+s0g1Zijm3lms50Nk/4tV2p8Y63c3F4Q3DAnK40Oi"
        + "kfOIwEj+Ny\n+zBRQssP3hPhTPOj/A7o3mZZwtL6x1sxpeu/nME1l5E=\n"
        + "-----END SIGNATURE-----\n", signature.getSignature());
    assertTrue(vote.getUnrecognizedLines().isEmpty());
  }

  @Test
  public void testNetworkStatusVersionNoLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'network-status-version' must be "
        + "contained in the first line.");
    VoteBuilder.createWithNetworkStatusVersionLine(null);
  }

  @Test
  public void testNetworkStatusVersionNewLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Blank lines are not allowed.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n");
  }

  @Test
  public void testNetworkStatusVersionNewLineSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal keyword in line ' '.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 3\n ");
  }

  @Test()
  public void testNetworkStatusVersionPrefixLineAtChar()
      throws DescriptorParseException {
    VoteBuilder.createWithNetworkStatusVersionLine(
        "@vote\nnetwork-status-version 3");
  }

  @Test
  public void testNetworkStatusVersionPrefixLine()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Unrecognized line 'directory-footer' in vote.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "directory-footer\nnetwork-status-version 3");
  }

  @Test
  public void testNetworkStatusVersionPrefixLinePoundChar()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Unrecognized line '#vote' in vote.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "#vote\nnetwork-status-version 3");
  }

  @Test
  public void testNetworkStatusVersionNoSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number "
        + "in line 'network-status-version'.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version");
  }

  @Test
  public void testNetworkStatusVersionOneSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number in "
        + "line 'network-status-version '.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version ");
  }

  @Test
  public void testNetworkStatusVersion42()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number in line "
        + "'network-status-version 42'.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version 42");
  }

  @Test
  public void testNetworkStatusVersionFourtyTwo()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal network status version number in line "
        + "'network-status-version FourtyTwo'.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        "network-status-version FourtyTwo");
  }

  @Test
  public void testVoteStatusNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'vote-status' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithVoteStatusLine(null);
  }

  @Test
  public void testNetworkStatusVersionSpaceBefore()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal keyword in line ' network-status-version 3'.");
    VoteBuilder.createWithNetworkStatusVersionLine(
        " network-status-version 3");
  }

  @Test
  public void testVoteStatusSpaceBefore() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal keyword in line ' vote-status vote'.");
    VoteBuilder.createWithVoteStatusLine(" vote-status vote");
  }

  @Test
  public void testVoteStatusNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown
        .expectMessage("Line 'vote-status' indicates that this is not a vote.");
    VoteBuilder.createWithVoteStatusLine("vote-status");
  }

  @Test
  public void testVoteStatusOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Line 'vote-status ' indicates that this is not a vote.");
    VoteBuilder.createWithVoteStatusLine("vote-status ");
  }

  @Test()
  public void testVoteStatusVoteOneSpace()
      throws DescriptorParseException {
    VoteBuilder.createWithVoteStatusLine("vote-status vote ");
  }

  @Test
  public void testVoteStatusConsensus() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'vote-status consensus' indicates that "
        + "this is not a vote.");
    VoteBuilder.createWithVoteStatusLine("vote-status consensus");
  }

  @Test
  public void testVoteStatusTheMagicVoteStatus()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'vote-status TheMagicVoteStatus' "
        + "indicates that this is not a vote.");
    VoteBuilder.createWithVoteStatusLine(
        "vote-status TheMagicVoteStatus");
  }

  @Test()
  public void testConsensusMethodNoLine()
      throws DescriptorParseException {
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithConsensusMethodsLine(null);
    assertNull(vote.getConsensusMethods());
  }

  @Test
  public void testConsensusMethodNoSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'consensus-methods' in vote.");
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods");
  }

  @Test
  public void testConsensusMethodOneSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'consensus-methods ' in vote.");
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods ");
  }

  @Test
  public void testConsensusMethodEleven()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal consensus method number in line "
        + "'consensus-methods eleven'.");
    VoteBuilder.createWithConsensusMethodsLine(
        "consensus-methods eleven");
  }

  @Test
  public void testConsensusMethodMinusOne()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal consensus method number in line "
        + "'consensus-methods -1'.");
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods -1");
  }

  @Test
  public void testConsensusMethodNinePeriod()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal consensus method number in line "
        + "'consensus-methods 99999999999999999999999999999999999999999"
        + "9999999999999999999'.");
    VoteBuilder.createWithConsensusMethodsLine("consensus-methods "
        + "999999999999999999999999999999999999999999999999999999999999");
  }

  @Test
  public void testConsensusMethodTwoLines()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Unrecognized line 'consensus-method 1' in vote.");
    VoteBuilder.createWithConsensusMethodsLine(
        "consensus-method 1\nconsensus-method 1");
  }

  @Test
  public void testPublishedNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'published' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithPublishedLine(null);
  }

  @Test
  public void testValidAfterNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'valid-after' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithValidAfterLine(null);
  }

  @Test
  public void testValidAfterNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'valid-after' does not contain a "
        + "timestamp at the expected position.");
    VoteBuilder.createWithValidAfterLine("valid-after");
  }

  @Test
  public void testValidAfterOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'valid-after ' does not contain a "
        + "timestamp at the expected position.");
    VoteBuilder.createWithValidAfterLine("valid-after ");
  }

  @Test
  public void testValidAfterLongAgo() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line 'valid-after "
        + "long ago'.");
    VoteBuilder.createWithValidAfterLine("valid-after long ago");
  }

  @Test
  public void testValidAfterFeb30() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line "
        + "'valid-after 2011-02-30 09:00:00'.");
    VoteBuilder.createWithValidAfterLine(
        "valid-after 2011-02-30 09:00:00");
  }

  @Test
  public void testFreshUntilNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'fresh-until' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithFreshUntilLine(null);
  }

  @Test
  public void testFreshUntilAroundTen() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line "
        + "'fresh-until 2011-11-30 around ten'.");
    VoteBuilder.createWithFreshUntilLine(
        "fresh-until 2011-11-30 around ten");
  }

  @Test
  public void testValidUntilTomorrowMorning()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line 'valid-until "
        + "tomorrow morning'.");
    VoteBuilder.createWithValidUntilLine(
        "valid-until tomorrow morning");
  }

  @Test
  public void testVotingDelayNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'voting-delay' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithVotingDelayLine(null);
  }

  @Test
  public void testVotingDelayNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Wrong number of values in line 'voting-delay'.");
    VoteBuilder.createWithVotingDelayLine("voting-delay");
  }

  @Test
  public void testVotingDelayOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown
        .expectMessage("Wrong number of values in line 'voting-delay '.");
    VoteBuilder.createWithVotingDelayLine("voting-delay ");
  }

  @Test
  public void testVotingDelayTriple() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Wrong number of values in line 'voting-delay 300 300 300'.");
    VoteBuilder.createWithVotingDelayLine(
        "voting-delay 300 300 300");
  }

  @Test
  public void testVotingDelaySingle() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Wrong number of values in line 'voting-delay 300'.");
    VoteBuilder.createWithVotingDelayLine("voting-delay 300");
  }

  @Test
  public void testVotingDelayOneTwo() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal values in line 'voting-delay one two'.");
    VoteBuilder.createWithVotingDelayLine("voting-delay one two");
  }

  @Test
  public void testClientVersionsComma() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal versions line 'client-versions ,'.");
    VoteBuilder.createWithClientVersionsLine("client-versions ,");
  }

  @Test
  public void testClientVersionsCommaVersion()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal versions line 'client-versions ,0.2.2.34'.");
    VoteBuilder.createWithClientVersionsLine(
        "client-versions ,0.2.2.34");
  }

  @Test
  public void testRecommendedClientProtocols21()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Invalid line 'recommended-client-protocols Cons=2-1'.");
    VoteBuilder.createWithRecommendedClientProtocolsLine(
        "recommended-client-protocols Cons=2-1");
  }

  @Test()
  public void testRecommendedRelayProtocols0()
      throws DescriptorParseException {
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithRecommendedRelayProtocolsLine(
        "recommended-relay-protocols Cons=0");
    assertEquals(new TreeSet<Long>(Arrays.asList(new Long[] { 0L })),
        vote.getRecommendedRelayProtocols().get("Cons"));
  }

  @Test
  public void testRequiredClientProtocols1Max()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Invalid line 'recommended-client-protocols Cons=1-4294967296'.");
    VoteBuilder.createWithRequiredClientProtocolsLine(
        "recommended-client-protocols Cons=1-4294967296");
  }

  @Test
  public void testRequiredRelayProtocolsMinus1()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown
        .expectMessage("Invalid line 'recommended-client-protocols Cons=-1'.");
    VoteBuilder.createWithRequiredRelayProtocolsLine(
        "recommended-client-protocols Cons=-1");
  }

  @Test()
  public void testPackageNone() throws DescriptorParseException {
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithPackageLines(null);
    assertNull(vote.getPackageLines());
  }

  @Test()
  public void testPackageOne() throws DescriptorParseException {
    String packageLine = "package shouldbesecond 0 http digest=digest";
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithPackageLines(packageLine);
    assertEquals(packageLine.substring("package ".length()),
        vote.getPackageLines().get(0));
  }

  @Test()
  public void testPackageTwo() throws DescriptorParseException {
    List<String> packageLines = Arrays.asList(
        "package shouldbesecond 0 http digest=digest",
        "package outoforder 0 http digest=digest");
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithPackageLines(packageLines.get(0)
        + "\n" + packageLines.get(1));
    for (int i = 0; i < packageLines.size(); i++) {
      assertEquals(packageLines.get(i).substring("package ".length()),
          vote.getPackageLines().get(i));
    }
  }

  @Test
  public void testPackageIncomplete() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Wrong number of values in line "
        + "'package shouldbesecond 0 http'.");
    String packageLine = "package shouldbesecond 0 http";
    ConsensusBuilder.createWithPackageLines(packageLine);
  }

  @Test
  public void testKnownFlagsNoLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'known-flags' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithKnownFlagsLine(null);
  }

  @Test
  public void testKnownFlagsNoSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("No known flags in line 'known-flags'.");
    VoteBuilder.createWithKnownFlagsLine("known-flags");
  }

  @Test
  public void testKnownFlagsOneSpace() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("No known flags in line 'known-flags '.");
    VoteBuilder.createWithKnownFlagsLine("known-flags ");
  }

  @Test()
  public void testFlagThresholdsLine() throws DescriptorParseException {
    VoteBuilder vb = new VoteBuilder();
    RelayNetworkStatusVote vote = vb.buildVote(true);
    assertEquals(693369L, vote.getStableUptime());
    assertEquals(153249L, vote.getStableMtbf());
    assertEquals(40960L, vote.getFastBandwidth());
    assertEquals(94.669, vote.getGuardWfu(), 0.001);
    assertEquals(691200L, vote.getGuardTk());
    assertEquals(174080L, vote.getGuardBandwidthIncludingExits());
    assertEquals(184320L, vote.getGuardBandwidthExcludingExits());
    assertEquals(1, vote.getEnoughMtbfInfo());
  }

  @Test()
  public void testFlagThresholdsNoLine() throws DescriptorParseException {
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithFlagThresholdsLine(null);
    assertEquals(-1L, vote.getStableUptime());
    assertEquals(-1L, vote.getStableMtbf());
    assertEquals(-1L, vote.getFastBandwidth());
    assertEquals(-1.0, vote.getGuardWfu(), 0.001);
    assertEquals(-1L, vote.getGuardTk());
    assertEquals(-1L, vote.getGuardBandwidthIncludingExits());
    assertEquals(-1L, vote.getGuardBandwidthExcludingExits());
    assertEquals(-1, vote.getEnoughMtbfInfo());
  }

  @Test()
  public void testFlagThresholdsAllZeroes()
      throws DescriptorParseException {
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithFlagThresholdsLine("flag-thresholds "
            + "stable-uptime=0 stable-mtbf=0 fast-speed=0 guard-wfu=0.0% "
            + "guard-tk=0 guard-bw-inc-exits=0 guard-bw-exc-exits=0 "
            + "enough-mtbf=0");
    assertEquals(0L, vote.getStableUptime());
    assertEquals(0L, vote.getStableMtbf());
    assertEquals(0L, vote.getFastBandwidth());
    assertEquals(0.0, vote.getGuardWfu(), 0.001);
    assertEquals(0L, vote.getGuardTk());
    assertEquals(0L, vote.getGuardBandwidthIncludingExits());
    assertEquals(0L, vote.getGuardBandwidthExcludingExits());
    assertEquals(0, vote.getEnoughMtbfInfo());
  }

  @Test
  public void testFlagThresholdsNoSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("No flag thresholds in line 'flag-thresholds'.");
    VoteBuilder.createWithFlagThresholdsLine("flag-thresholds");
  }

  @Test
  public void testFlagThresholdsOneSpace()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("No flag thresholds in line 'flag-thresholds '.");
    VoteBuilder.createWithFlagThresholdsLine("flag-thresholds ");
  }

  @Test
  public void testFlagThresholdDuplicate()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'flag-thresholds' is contained 2 "
        + "times, but must be contained at most once.");
    VoteBuilder vb = new VoteBuilder();
    vb.flagThresholdsLine = vb.flagThresholdsLine + "\n"
        + vb.flagThresholdsLine;
    vb.buildVote(true);
  }

  @Test
  public void testNicknameMissing() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'dir-source  80550987E1D626E3EBA5E"
        + "5E75A458DE0626D088C 208.83.223.34 208.83.223.34 443 80' in vote.");
    VoteBuilder.createWithDirSourceLine("dir-source  "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test
  public void testNicknameTooLong() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal nickname in line 'dir-source "
        + "urrassssssssssssssssssssssssssssssssssssssssssssssss 80550987E1D626"
        + "E3EBA5E5E75A458DE0626D088C 208.83.223.34 208.83.223.34 443 80'.");
    VoteBuilder.createWithDirSourceLine("dir-source "
        + "urrassssssssssssssssssssssssssssssssssssssssssssssss "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test
  public void testNicknameIllegalCharacters()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal nickname in line 'dir-source urra$ "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80'.");
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

  @Test
  public void testFingerprintTooShort() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D 208.83.223.34 208.83.223.34 "
        + "443 80'.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test
  public void testFingerprintTooLong() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C8055 208.83.223.34 "
        + "208.83.223.34 443 80'.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C8055 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test
  public void testFingerprintIllegalCharacters()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'dir-source urras "
        + "ABCDEFGHIJKLM6E3EBA5E5E75A458DE0626D088C 208.83.223.34 208.83.223.34"
        + " 443 80'.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "ABCDEFGHIJKLM6E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 443 80");
  }

  @Test
  public void testFingerprintMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'dir-source urras  "
        + "208.83.223.34 208.83.223.34 443 80' in vote.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + " 208.83.223.34 208.83.223.34 443 80");
  }

  @Test()
  public void testHostname256()
      throws DescriptorParseException {
    /* This test doesn't fail, because we're not parsing the hostname. */
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 256.256.256.256 "
        + "208.83.223.34 443 80");
    assertEquals("256.256.256.256", vote.getHostname());
  }

  @Test
  public void testHostnameMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C  208.83.223.34 443 80' "
        + "in vote.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C  208.83.223.34 443 "
        + "80");
  }

  @Test
  public void testAddress256()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'256.256.256.256' in line 'dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 256.256.256."
        + "256 443 80' is not a valid IPv4 address.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "256.256.256.256 443 80");
  }

  @Test
  public void testAddressMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34  "
        + "443 80' in vote.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34  443 "
        + "80");
  }

  @Test
  public void testDirPortMinus443()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'-443' in line 'dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 -443 80' is not a valid port number.");
    VoteBuilder.createWithDirSourceLine("dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 "
        + "208.83.223.34 -443 80");
  }

  @Test
  public void testDirPortFourFourThree()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'four-four-three' in line 'dir-source urras "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C 208.83.223.34 208.83.223.34"
        + " four-four-three 80' is not a valid port number.");
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

  @Test
  public void testOrPortMissing() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'dir-source urras 80550987E1D626E3E"
        + "BA5E5E75A458DE0626D088C 208.83.223.34 208.83.223.34 443 ' in vote.");
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

  @Test
  public void testDirSourceLineMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-source' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithDirSourceLine(null);
  }

  @Test
  public void testDirSourceLineDuplicate()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-source' is contained 2 times, "
        + "but must be contained exactly once.");
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

  @Test
  public void testContactLineDuplicate()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'contact' is contained 2 times, "
        + "but must be contained at most once.");
    VoteBuilder.createWithContactLine("contact 4096R/E012B42D Jacob "
        + "Appelbaum <jacob@appelbaum.net>\ncontact 4096R/E012B42D Jacob "
        + "Appelbaum <jacob@appelbaum.net>");
  }

  @Test
  public void testSharedRandParticipateLineDuplicate()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'shared-rand-participate' is contained "
        + "2 times, but must be contained at most once.");
    VoteBuilder.createWithSharedRandParticipateLine("shared-rand-participate\n"
        + "shared-rand-participate");
  }

  @Test
  public void testSharedRandParticipateLineArg()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown
        .expectMessage("Illegal line 'shared-rand-participate 1' in vote.");
    VoteBuilder.createWithSharedRandParticipateLine(
        "shared-rand-participate 1");
  }

  @Test()
  public void testSharedRandCommitLinesEmpty() throws DescriptorParseException {
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithSharedRandCommitLines(null);
    assertNull(vote.getSharedRandCommitLines());
  }

  @Test
  public void testSharedRandPreviousValueBeforeNumReveals()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'shared-rand-previous-value "
        + "grwbnD6I40odtsdtWYxqs0DvPweCur6qG2Fo5p5ivS4= 8' in vote.");
    VoteBuilder.createWithSharedRandPreviousValueLine(
        "shared-rand-previous-value "
        + "grwbnD6I40odtsdtWYxqs0DvPweCur6qG2Fo5p5ivS4= 8");
  }

  @Test
  public void testSharedRandCurrentNoNumReveals()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'shared-rand-current-value "
        + "D88plxd8YeLfCIVAR9gjiFlWB1WqpC53kWr350o1pzw=' in vote.");
    VoteBuilder.createWithSharedRandCurrentValueLine(
        "shared-rand-current-value "
            + "D88plxd8YeLfCIVAR9gjiFlWB1WqpC53kWr350o1pzw=");
  }

  @Test()
  public void testLegacyDirKeyLine() throws DescriptorParseException {
    RelayNetworkStatusVote vote = VoteBuilder.createWithLegacyDirKeyLine(
        "legacy-dir-key 81349FC1F2DBA2C2C11B45CB9706637D480AB913");
    assertEquals("81349FC1F2DBA2C2C11B45CB9706637D480AB913",
        vote.getLegacyDirKey());
  }

  @Test
  public void testLegacyDirKeyLineNoId() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'legacy-dir-key '.");
    VoteBuilder.createWithLegacyDirKeyLine("legacy-dir-key ");
  }

  @Test
  public void testDirKeyCertificateVersionLineMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-key-certificate-version' is "
        + "contained 0 times, but must be contained exactly once.");
    VoteBuilder.createWithDirKeyCertificateVersionLine(null);
  }

  @Test
  public void testDirKeyCertificateVersionLineDuplicate()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-key-certificate-version' is "
        + "contained 2 times, but must be contained exactly once.");
    VoteBuilder.createWithDirKeyCertificateVersionLine(
        "dir-key-certificate-version 3\ndir-key-certificate-version 3");
  }

  @Test
  public void testFingerprintLineMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'fingerprint' is contained 0 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithFingerprintLine(null);
  }

  @Test
  public void testFingerprintLineDuplicate()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'fingerprint' is contained 2 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithFingerprintLine("fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C\nfingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C");
  }

  @Test
  public void testFingerprintLineTooLong()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C8055'.");
    VoteBuilder.createWithFingerprintLine("fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D088C8055");
  }

  @Test
  public void testFingerprintLineTooShort()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal hex string in line 'fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D'.");
    VoteBuilder.createWithFingerprintLine("fingerprint "
        + "80550987E1D626E3EBA5E5E75A458DE0626D");
  }

  @Test
  public void testDirKeyPublished3011()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line "
        + "'dir-key-published 3011-04-27 05:34:37'.");
    VoteBuilder.createWithDirKeyPublishedLine("dir-key-published "
        + "3011-04-27 05:34:37");
  }

  @Test
  public void testDirKeyPublishedRecentlyAtNoon()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal timestamp format in line "
        + "'dir-key-published recently 12:00:00'.");
    VoteBuilder.createWithDirKeyPublishedLine("dir-key-published "
        + "recently 12:00:00");
  }

  @Test
  public void testDirKeyPublishedRecentlyNoTime()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Line 'dir-key-published recently' does not "
        + "contain a timestamp at the expected position.");
    VoteBuilder.createWithDirKeyPublishedLine("dir-key-published "
        + "recently");
  }

  @Test
  public void testDirKeyExpiresSoonAtNoon()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal timestamp format in line 'dir-key-expires soon 12:00:00'.");
    VoteBuilder.createWithDirKeyExpiresLine("dir-key-expires "
        + "soon 12:00:00");
  }

  @Test
  public void testDirKeyExpiresLineMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-key-expires' is contained 0 times,"
        + " but must be contained exactly once.");
    VoteBuilder.createWithDirKeyExpiresLine(null);
  }

  @Test
  public void testDirKeyExpiresLineDuplicate()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-key-expires' is contained 2 times, "
        + "but must be contained exactly once.");
    VoteBuilder.createWithDirKeyExpiresLine("dir-key-expires 2012-04-27 "
        + "05:34:37\ndir-key-expires 2012-04-27 05:34:37");
  }

  @Test
  public void testDirIdentityKeyLinesMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-identity-key' is contained 0 times,"
        + " but must be contained exactly once.");
    VoteBuilder.createWithDirIdentityKeyLines(null);
  }

  @Test
  public void testDirSigningKeyLinesMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-signing-key' is contained 0"
        + " times, but must be contained exactly once.");
    VoteBuilder.createWithDirSigningKeyLines(null);
  }

  @Test()
  public void testDirKeyCrosscertLinesMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirKeyCrosscertLines(null);
  }

  @Test
  public void testDirKeyCertificationLinesMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'dir-key-certification' is contained "
        + "0 times, but must be contained exactly once.");
    VoteBuilder.createWithDirKeyCertificationLines(null);
  }

  @Test()
  public void testDirectoryFooterLineMissing()
      throws DescriptorParseException {
    VoteBuilder.createWithDirectoryFooterLine(null);
  }

  @Test
  public void testDirectorySignaturesLinesMissing()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'directory-signature' is contained 0 "
        + "times, but must be contained at least once.");
    VoteBuilder.createWithDirectorySignatureLines(null);
  }

  @Test()
  public void testDirectorySignaturesLinesTwoAlgorithms()
      throws DescriptorParseException {
    String identitySha256 = "32519E5CB7254AB5A94CC9925EC7676E53D5D52EEAB7"
        + "914BD3ED751E537CAFCC";
    String signingKeyDigestSha256 = "5A59D99C17831B9254422B6C5AA10CC59381"
        + "6CAA5241E22ECAE8BBB4E8E9D1FC";
    String signatureSha256 = "-----BEGIN SIGNATURE-----\n"
        + "x57Alc424/zHS73SHokghGtNBVrBjtUz+gSL5w9AHGKUQcMyfw4Z9aDlKpTbFc"
        + "5W\nnyIvFmM9C2OAH0S1+a647HHIxhE0zKf4+yKSwzqSyL6sbKQygVlJsRHNRr"
        + "cFg8lp\nqBxEwvxQoA4xEDqnerR92pbK9l42nNLiKOcoReUqbbQ=\n"
        + "-----END SIGNATURE-----";
    String identitySha1 = "80550987E1D626E3EBA5E5E75A458DE0626D088C";
    String signingKeyDigestSha1 =
        "EEB9299D295C1C815E289FBF2F2BBEA5F52FDD19";
    String signatureSha1 = "-----BEGIN SIGNATURE-----\n"
        + "iHEU3Iidya5RIrjyYgv8tlU0R+rF56/3/MmaaZi0a67e7ZkISfQ4dghScHxnF3"
        + "Yh\nrXVaaoP07r6Ta+s0g1Zijm3lms50Nk/4tV2p8Y63c3F4Q3DAnK40OikfOI"
        + "wEj+Ny\n+zBRQssP3hPhTPOj/A7o3mZZwtL6x1sxpeu/nME1l5E=\n"
        + "-----END SIGNATURE-----";
    String signaturesLines = String.format(
        "directory-signature sha256 %s %s\n%s\n"
        + "directory-signature %s %s\n%s", identitySha256,
        signingKeyDigestSha256, signatureSha256, identitySha1,
        signingKeyDigestSha1, signatureSha1);
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithDirectorySignatureLines(signaturesLines);
    assertEquals(2, vote.getSignatures().size());
    DirectorySignature firstSignature = vote.getSignatures().get(0);
    assertEquals("sha256", firstSignature.getAlgorithm());
    assertEquals(identitySha256, firstSignature.getIdentity());
    assertEquals(signingKeyDigestSha256,
        firstSignature.getSigningKeyDigestSha1Hex());
    assertEquals(signatureSha256 + "\n", firstSignature.getSignature());
    DirectorySignature secondSignature = vote.getSignatures().get(1);
    assertEquals("sha1", secondSignature.getAlgorithm());
    assertEquals(identitySha1, secondSignature.getIdentity());
    assertEquals(signingKeyDigestSha1,
        secondSignature.getSigningKeyDigestSha1Hex());
    assertEquals(signatureSha1 + "\n", secondSignature.getSignature());
    assertEquals(signingKeyDigestSha1, vote.getSigningKeyDigest());
    assertEquals("c0d58c8d3c3695526f6eb5c0d9f8452b2234d303",
        vote.getDigestSha1Hex());
  }

  @Test()
  public void testDirectorySignaturesLinesTwoAlgorithmsSameDigests()
      throws DescriptorParseException {
    String signaturesLines = "directory-signature 00 00\n"
        + "-----BEGIN SIGNATURE-----\n00\n-----END SIGNATURE-----\n"
        + "directory-signature sha256 00 00\n"
        + "-----BEGIN SIGNATURE-----\n00\n-----END SIGNATURE-----";
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithDirectorySignatureLines(signaturesLines);
    assertEquals(2, vote.getSignatures().size());
  }

  @Test
  public void testUnrecognizedHeaderLineFail()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Unrecognized line 'unrecognized-line 1' in vote.");
    String unrecognizedLine = "unrecognized-line 1";
    VoteBuilder.createWithUnrecognizedHeaderLine(unrecognizedLine, true);
  }

  @Test()
  public void testUnrecognizedHeaderLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusVote vote = VoteBuilder
        .createWithUnrecognizedHeaderLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, vote.getUnrecognizedLines());
  }

  @Test
  public void testUnrecognizedDirSourceLineFail()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Unrecognized line 'unrecognized-line 1' in vote.");
    String unrecognizedLine = "unrecognized-line 1";
    VoteBuilder.createWithUnrecognizedDirSourceLine(unrecognizedLine,
        true);
  }

  @Test()
  public void testUnrecognizedDirSourceLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusVote vote = VoteBuilder
        .createWithUnrecognizedDirSourceLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, vote.getUnrecognizedLines());
  }

  @Test
  public void testUnrecognizedFooterLineFail()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown
      .expectMessage("Unrecognized line 'unrecognized-line 1' in vote.");
    String unrecognizedLine = "unrecognized-line 1";
    VoteBuilder.createWithUnrecognizedFooterLine(unrecognizedLine, true);
  }

  @Test()
  public void testUnrecognizedFooterLineIgnore()
      throws DescriptorParseException {
    String unrecognizedLine = "unrecognized-line 1";
    RelayNetworkStatusVote vote = VoteBuilder
        .createWithUnrecognizedFooterLine(unrecognizedLine, false);
    List<String> unrecognizedLines = new ArrayList<>();
    unrecognizedLines.add(unrecognizedLine);
    assertEquals(unrecognizedLines, vote.getUnrecognizedLines());
  }

  @Test()
  public void testIdEd25519MasterKey()
      throws DescriptorParseException {
    String masterKey25519 = "8RH34kO07Pp+XYwzdoATVyCibIvmbslUjRkAm7J4IA8";
    List<String> statusEntries = new ArrayList<>();
    statusEntries.add("r PDrelay1 AAFJ5u9xAqrKlpDW6N0pMhJLlKs "
        + "bgJiI/la3e9u0K7cQ5pMSXhigHI 2015-12-01 04:54:30 95.215.44.189 "
        + "8080 0\n"
        + "id ed25519 " + masterKey25519);
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithStatusEntries(statusEntries);
    String fingerprint = vote.getStatusEntries().firstKey();
    assertEquals(masterKey25519,
        vote.getStatusEntry(fingerprint).getMasterKeyEd25519());
  }

  @Test()
  public void testIdEd25519None()
      throws DescriptorParseException {
    List<String> statusEntries = new ArrayList<>();
    statusEntries.add("r MathematicalApology AAPJIrV9nhfgTYQs0vsTghFaP2A "
        + "uA7p0m68O8ILXsf3aLZUj0EvDNE 2015-12-01 18:01:49 172.99.69.177 "
        + "443 9030\n"
        + "id ed25519 none");
    RelayNetworkStatusVote vote =
        VoteBuilder.createWithStatusEntries(statusEntries);
    String fingerprint = vote.getStatusEntries().firstKey();
    assertEquals("none",
        vote.getStatusEntry(fingerprint).getMasterKeyEd25519());
  }

  @Test
  public void testIdRsa1024None()
      throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Illegal line 'id rsa1024 none'.");
    List<String> statusEntries = new ArrayList<>();
    statusEntries.add("r MathematicalApology AAPJIrV9nhfgTYQs0vsTghFaP2A "
        + "uA7p0m68O8ILXsf3aLZUj0EvDNE 2015-12-01 18:01:49 172.99.69.177 "
        + "443 9030\n"
        + "id rsa1024 none");
    VoteBuilder.createWithStatusEntries(statusEntries);
  }
}

