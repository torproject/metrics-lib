/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;

/* Contains a network status vote. */
public interface RelayNetworkStatusVote extends Descriptor {

  /* Return the network status version. */
  public int getNetworkStatusVersion();

  /* Return the consensus method. */
  public List<Integer> getConsensusMethods();

  /* Return the publication time in milliseconds. */
  public long getPublishedMillis();

  /* Return the valid-after time in milliseconds. */
  public long getValidAfterMillis();

  /* Return the fresh-until time in milliseconds. */
  public long getFreshUntilMillis();

  /* Return the valid-until time in milliseconds. */
  public long getValidUntilMillis();

  /* Return the VoteSeconds time in seconds. */
  public long getVoteSeconds();

  /* Return the DistSeconds time in seconds. */
  public long getDistSeconds();

  /* Return recommended server versions or null if the authority doesn't
   * recommend server versions. */
  public List<String> getRecommendedServerVersions();

  /* Return recommended client versions or null if the authority doesn't
   * recommend server versions. */
  public List<String> getRecommendedClientVersions();

  /* Return known relay flags. */
  public SortedSet<String> getKnownFlags();

  /* Return consensus parameters. */
  public SortedMap<String, Integer> getConsensusParams();

  /* Return the directory nickname. */
  public String getNickname();

  /* Return the directory identity. */
  public String getIdentity();

  /* Return the IP address. */
  public String getAddress();

  /* Return the DiRPort. */
  public int getDirport();

  /* Return the ORPort. */
  public int getOrport();

  /* Return the contact line. */
  public String getContactLine();

  /* Return the directory key certificate version. */
  public int getDirKeyCertificateVersion();

  /* Return the legacy key or null if the directory authority does not use
   * a legacy key. */
  public String getLegacyKey();

  /* Return the directory key publication timestamp. */
  public long getDirKeyPublishedMillis();

  /* Return the directory key expiration timestamp. */
  public long getDirKeyExpiresMillis();

  /* Return the signing key digest. */
  public String getSigningKeyDigest();

  /* Return status entries, one for each contained relay. */
  public SortedMap<String, NetworkStatusEntry> getStatusEntries();

  /* Return whether a status entry with the given fingerprint exists. */
  public boolean containsStatusEntry(String fingerprint);

  /* Return a status entry by fingerprint or null if no such status entry
   * exists. */
  public NetworkStatusEntry getStatusEntry(String fingerprint);

  /* Return directory signatures. */
  public SortedMap<String, String> getDirectorySignatures();
}

