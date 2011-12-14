/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;

/* Contains a network status consensus. */
public interface RelayNetworkStatusConsensus extends Descriptor {

  /* Return the network status version. */
  public int getNetworkStatusVersion();

  /* Return the consensus method. */
  public int getConsensusMethod();

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

  /* Return recommended server versions or null if the consensus doesn't
   * contain recommended server versions. */
  public SortedSet<String> getRecommendedServerVersions();

  /* Return recommended client versions or null if the consensus doesn't
   * contain recommended client versions. */
  public SortedSet<String> getRecommendedClientVersions();

  /* Return known relay flags. */
  public SortedSet<String> getKnownFlags();

  /* Return consensus parameters or null if the consensus doesn't contain
   * consensus parameters. */
  public SortedMap<String, Integer> getConsensusParams();

  /* Return dir-source entries representing the directories of which
   * votes are contained in this consensus. */
  public SortedMap<String, DirSourceEntry> getDirSourceEntries();

  /* Return status entries, one for each contained relay. */
  public SortedMap<String, NetworkStatusEntry> getStatusEntries();

  /* Return whether a status entry with the given fingerprint exists. */
  public boolean containsStatusEntry(String fingerprint);

  /* Return a status entry by fingerprint or null if no such status entry
   * exists. */
  public NetworkStatusEntry getStatusEntry(String fingerprint);

  /* Return directory signatures. */
  public SortedMap<String, String> getDirectorySignatures();

  /* Return bandwidth weights or null if the consensus doesn't contain
   * bandwidth weights. */
  public SortedMap<String, Integer> getBandwidthWeights();
}

