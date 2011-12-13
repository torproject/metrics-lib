/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusVote;

/* Contains a network status vote. */
/* TODO This class is sharing a lot of parsing code with the consensus
 * class.  Should there be an abstract super class for the two? */
public class RelayNetworkStatusVoteImpl
    implements RelayNetworkStatusVote {

  protected static List<RelayNetworkStatusVote> parseVotes(
      byte[] voteBytes) {
    List<RelayNetworkStatusVote> parsedVotes =
        new ArrayList<RelayNetworkStatusVote>();
    String startToken = "network-status-version 3";
    String splitToken = "\n" + startToken;
    String ascii = new String(voteBytes);
    int length = voteBytes.length, start = ascii.indexOf(startToken);
    while (start < length) {
      int end = ascii.indexOf(splitToken, start);
      if (end < 0) {
        end = length;
      } else {
        end += 1;
      }
      byte[] descBytes = new byte[end - start];
      System.arraycopy(voteBytes, start, descBytes, 0, end - start);
      RelayNetworkStatusVote parsedVote =
          new RelayNetworkStatusVoteImpl(descBytes);
      parsedVotes.add(parsedVote);
      start = end;
    }
    return parsedVotes;
  }

  protected RelayNetworkStatusVoteImpl(byte[] voteBytes) {
    this.voteBytes = voteBytes;
    this.parseVoteBytes();
    this.checkConsistency();
    /* TODO Find a way to handle parse and consistency-check problems. */
  }

  private void parseVoteBytes() {
    String line = null;
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.voteBytes)));
      SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
          "yyyy-MM-dd HH:mm:ss");
      dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      StringBuilder dirSourceEntryLines = null, statusEntryLines = null;
      boolean skipCrypto = false;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("network-status-version ")) {
          this.networkStatusVersion = Integer.parseInt(line.substring(
              "network-status-version ".length()));
        } else if (line.startsWith("vote-status ")) {
          if (!line.equals("vote-status vote")) {
            throw new RuntimeException("Line '" + line + "' indicates "
                + "that this string is not a vote.  Aborting parsing.");
          }
        } else if (line.startsWith("consensus-methods ")) {
          for (String consensusMethodString : line.substring(
              "consensus-methods ".length()).split(" ")) {
            this.consensusMethods.add(Integer.parseInt(
            consensusMethodString));
          }
        } else if (line.startsWith("published ")) {
          this.publishedMillis = dateTimeFormat.parse(
              line.substring("published ".length())).getTime();
        } else if (line.startsWith("valid-after ")) {
          this.validAfterMillis = dateTimeFormat.parse(
              line.substring("valid-after ".length())).getTime();
        } else if (line.startsWith("fresh-until ")) {
          this.freshUntilMillis = dateTimeFormat.parse(
              line.substring("fresh-until ".length())).getTime();
        } else if (line.startsWith("valid-until ")) {
          this.validUntilMillis = dateTimeFormat.parse(
              line.substring("valid-until ".length())).getTime();
        } else if (line.startsWith("voting-delay ")) {
          for (String votingDelayString : line.substring(
              "voting-delay ".length()).split(" ")) {
            this.votingDelay.add(Long.parseLong(votingDelayString));
          }
        } else if (line.startsWith("client-versions ")) {
          this.recommendedClientVersions.addAll(
              Arrays.asList(line.split(" ")[1].split(",")));
        } else if (line.startsWith("server-versions ")) {
          this.recommendedServerVersions.addAll(
              Arrays.asList(line.split(" ")[1].split(",")));
        } else if (line.startsWith("known-flags ")) {
          for (String flag : line.substring("known-flags ".length()).
              split(" ")) {
            this.knownFlags.add(flag);
          }
        } else if (line.startsWith("params ")) {
          if (line.length() > "params ".length()) {
            for (String param :
                line.substring("params ".length()).split(" ")) {
              String paramName = param.split("=")[0];
              String paramValue = param.split("=")[1];
              this.consensusParams.put(paramName, paramValue);
            }
          }
        } else if (line.startsWith("dir-source ")) {
          String[] parts = line.split(" ");
          this.nickname = parts[1];
          this.identity = parts[2];
          this.address = parts[4];
          this.dirPort = Integer.parseInt(parts[5]);
          this.orPort = Integer.parseInt(parts[6]);
          /* TODO Add code for parsing legacy dir sources. */
        } else if (line.startsWith("contact ")) {
          this.contactLine = line.substring("contact ".length());
        } else if (line.startsWith("dir-key-certificate-version ")) {
          this.dirKeyCertificateVersion = Integer.parseInt(line.substring(
              "dir-key-certificate-version ".length()));
        } else if (line.startsWith("fingerprint ")) {
          /* Nothing new to learn here.  We already know the fingerprint
           * from the dir-source line. */
        } else if (line.startsWith("dir-key-published ")) {
          this.dirKeyPublishedMillis = dateTimeFormat.parse(
              line.substring("dir-key-published ".length())).getTime();
        } else if (line.startsWith("dir-key-expires ")) {
          this.dirKeyExpiresMillis = dateTimeFormat.parse(
              line.substring("dir-key-expires ".length())).getTime();
        } else if (line.equals("dir-identity-key") ||
            line.equals("dir-signing-key") ||
            line.equals("dir-key-crosscert") ||
            line.equals("dir-key-certification")) {
          /* Ignore crypto parts for now. */
        } else if (line.startsWith("r ") ||
            line.equals("directory-footer")) {
          if (statusEntryLines != null) {
            NetworkStatusEntryImpl statusEntry =
                new NetworkStatusEntryImpl(
                statusEntryLines.toString().getBytes());
            this.statusEntries.put(statusEntry.getFingerprint(),
                statusEntry);
            statusEntryLines = null;
          }
          if (line.startsWith("r ")) {
            statusEntryLines = new StringBuilder();
            statusEntryLines.append(line + "\n");
          }
        } else if (line.startsWith("s ") || line.equals("s") ||
            line.startsWith("opt v ") || line.startsWith("w ") ||
            line.startsWith("p ") || line.startsWith("m ")) {
          statusEntryLines.append(line + "\n");
        } else if (line.startsWith("directory-signature ")) {
          String[] parts = line.split(" ");
          String identity = parts[1];
          String signingKeyDigest = parts[2];
          this.directorySignatures.put(identity, signingKeyDigest);
        } else if (line.startsWith("-----BEGIN")) {
          skipCrypto = true;
        } else if (line.startsWith("-----END")) {
          skipCrypto = false;
        } else if (!skipCrypto) {
          throw new RuntimeException("Unrecognized line '" + line + "'.");
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    } catch (ParseException e) {
      /* TODO Handle me correctly. */
      throw new RuntimeException("Parse error in line '" + line + "'.");
    } catch (NumberFormatException e) {
      /* TODO Handle me.  In theory, we shouldn't catch runtime
       * exceptions, but in this case it keeps the parsing code small. */
    } catch (ArrayIndexOutOfBoundsException e) {
      /* TODO Handle me.  In theory, we shouldn't catch runtime
       * exceptions, but in this case it keeps the parsing code small. */
    }
  }

  private byte[] voteBytes;
  public byte[] getRawDescriptorBytes() {
    return this.voteBytes;
  }

  private int networkStatusVersion;
  public int getNetworkStatusVersion() {
    return this.networkStatusVersion;
  }

  private List<Integer> consensusMethods = new ArrayList<Integer>();
  public List<Integer> getConsensusMethods() {
    return this.consensusMethods;
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private long validAfterMillis;
  public long getValidAfterMillis() {
    return this.validAfterMillis;
  }

  private long freshUntilMillis;
  public long getFreshUntilMillis() {
    return this.freshUntilMillis;
  }

  private long validUntilMillis;
  public long getValidUntilMillis() {
    return this.validUntilMillis;
  }

  private List<Long> votingDelay = new ArrayList<Long>();
  public List<Long> getVotingDelay() {
    return new ArrayList<Long>(this.votingDelay);
  }

  private SortedSet<String> recommendedClientVersions =
      new TreeSet<String>();
  public SortedSet<String> getRecommendedClientVersions() {
    return new TreeSet<String>(this.recommendedClientVersions);
  }

  private SortedSet<String> recommendedServerVersions =
      new TreeSet<String>();
  public SortedSet<String> getRecommendedServerVersions() {
    return new TreeSet<String>(this.recommendedServerVersions);
  }

  private SortedSet<String> knownFlags = new TreeSet<String>();
  public SortedSet<String> getKnownFlags() {
    return new TreeSet<String>(this.knownFlags);
  }

  private SortedMap<String, String> consensusParams =
      new TreeMap<String, String>();
  public SortedMap<String, String> getConsensusParams() {
    return new TreeMap<String, String>(this.consensusParams);
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String identity;
  public String getIdentity() {
    return this.identity;
  }

  private String address;
  public String getAddress() {
    return this.address;
  }

  private int dirPort;
  public int getDirport() {
    return this.dirPort;
  }

  private int orPort;
  public int getOrport() {
    return this.orPort;
  }

  private String contactLine;
  public String getContactLine() {
    return this.contactLine;
  }

  private int dirKeyCertificateVersion;
  public int getDirKeyCertificateVersion() {
    return this.dirKeyCertificateVersion;
  }

  private long dirKeyPublishedMillis;
  public long getDirKeyPublishedMillis() {
    return this.dirKeyPublishedMillis;
  }

  private long dirKeyExpiresMillis;
  public long getDirKeyExpiresMillis() {
    return this.dirKeyExpiresMillis;
  }

  private String signingKeyDigest;
  public String getSigningKeyDigest() {
    return this.signingKeyDigest;
  }

  private SortedMap<String, NetworkStatusEntry> statusEntries =
      new TreeMap<String, NetworkStatusEntry>();
  public SortedMap<String, NetworkStatusEntry> getStatusEntries() {
    return new TreeMap<String, NetworkStatusEntry>(this.statusEntries);
  }
  public boolean containsStatusEntry(String fingerprint) {
    return this.statusEntries.containsKey(fingerprint);
  }
  public NetworkStatusEntry getStatusEntry(String fingerprint) {
    return this.statusEntries.get(fingerprint);
  }


  private SortedMap<String, String> directorySignatures =
      new TreeMap<String, String>();
  public SortedMap<String, String> getDirectorySignatures() {
    return new TreeMap<String, String>(this.directorySignatures);
  }

  private void checkConsistency() {
    if (this.networkStatusVersion == 0) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'network-status-version' line.");
    }
    if (this.validAfterMillis == 0L) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'valid-after' line.");
    }
    if (this.freshUntilMillis == 0L) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'fresh-until' line.");
    }
    if (this.validUntilMillis == 0L) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'valid-until' line.");
    }
    if (this.votingDelay.isEmpty()) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'voting-delay' line.");
    }
    if (this.knownFlags.isEmpty()) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'known-flags' line.");
    }
    if (this.statusEntries.isEmpty()) {
      throw new RuntimeException("Consensus doesn't contain any 'r' "
          + "lines.");
    }
  }
}

