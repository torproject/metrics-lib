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

  /* Return the minimum uptime in seconds that this authority requires for
   * assigning the Stable flag, or -1 if the authority doesn't report this
   * value. */
  public long getStableUptime();

  /* Return the minimum MTBF (mean time between failure) that this
   * authority requires for assigning the Stable flag, or -1 if the
   * authority doesn't report this value. */
  public long getStableMtbf();

  /* Return the minimum bandwidth that this authority requires for
   * assigning the Fast flag, or -1 if the authority doesn't report this
   * value. */
  public long getFastBandwidth();

  /* Return the minimum WFU (weighted fractional uptime) in percent that
   * this authority requires for assigning the Guard flag, or -1.0 if the
   * authority doesn't report this value. */
  public double getGuardWfu();

  /* Return the minimum time in seconds that this authority needs to know
   * about a relay before assigning the Guard flag, or -1 if the authority
   * doesn't report this information. */
  public long getGuardTk();

  /* Return the minimum bandwidth that this authority requires for
   * assigning the Guard flag if exits can be guards, or -1 if the
   * authority doesn't report this value. */
  public long getGuardBandwidthIncludingExits();

  /* Return the minimum bandwidth that this authority requires for
   * assigning the Guard flag if exits can not be guards, or -1 if the
   * authority doesn't report this value. */
  public long getGuardBandwidthExcludingExits();

  /* Return 1 if the authority has measured enough MTBF info to use the
   * MTBF requirement instead of the uptime requirement for assigning the
   * Stable flag, 0 if not, or -1 if the authority doesn't report this
   * information. */
  public int getEnoughMtbfInfo();

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

  /* Return the legacy dir key or null if the directory authority does not
   * use a legacy dir key. */
  public String getLegacyDirKey();

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
  public SortedMap<String, DirectorySignature> getDirectorySignatures();
}

