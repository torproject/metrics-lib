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

  /* Return a list of the voting-delay times in seconds. */
  public List<Long> getVotingDelay();

  /* Return cecommended server versions. */
  public SortedSet<String> getRecommendedServerVersions();

  /* Return recommended client versions. */
  public SortedSet<String> getRecommendedClientVersions();

  /* Return known relay flags. */
  public SortedSet<String> getKnownFlags();

  /* Return consensus parameters. */
  public SortedMap<String, String> getConsensusParams();

  /* Return dir-source entries representing the directories of which
   * votes are contained in this consensus. */
  public SortedMap<String, DirSourceEntry> getDirSourceEntries();

  /* Return status entries, one for each contained relay. */
  public SortedMap<String, NetworkStatusEntry> getStatusEntries();

  /* Return directory signatures. */
  public SortedMap<String, String> getDirectorySignatures();

  /* Return bandwidth weights. */
  public SortedMap<String, String> getBandwidthWeights();
}

