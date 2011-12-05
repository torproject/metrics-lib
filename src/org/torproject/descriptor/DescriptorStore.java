/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;
import java.util.Set;

/* Store previously downloaded descriptors or descriptors in a local
 * directory and make them available for further processing. */
public interface DescriptorStore {

  /* Return whether a previously set global request timeout has expired
   * when downloading descriptors. */
  public boolean globalTimeoutHasExpired();

  /* Return a list of descriptor requests in chronological order of
   * starting them. */
  public List<DescriptorRequest> getDescriptorRequests();

  /* Return a list of descriptor files in the order in which they were
   * read from disk. */
  public List<DescriptorFile> getDescriptorFiles();

  /* Return all relay network status consensuses. */
  public Set<RelayNetworkStatusConsensus>
      getAllRelayNetworkStatusConsensuses();

  /* Return all relay network status votes. */
  public Set<RelayNetworkStatusVote> getAllRelayNetworkStatusVotes();

  /* Return all relay server descriptors. */
  public Set<RelayServerDescriptor> getAllRelayServerDescriptors();

  /* Return all relay extra-info descriptors. */
  public Set<RelayExtraInfoDescriptor> getAllRelayExtraInfoDescriptors();

  /* Return all bridge network statuses. */
  public Set<BridgeNetworkStatus> getAllBridgeNetworkStatuses();

  /* Return all bridge server descriptors. */
  public Set<BridgeServerDescriptor> getAllBridgeServerDescriptors();

  /* Return all bridge extra-info descriptors. */
  public Set<BridgeExtraInfoDescriptor>
      getAllBridgeExtraInfoDescriptors();

  /* TODO Add methods to query the descriptor store for specific
   * descriptors, rather than returning sets of all descriptors and have
   * the application implement its own query logic. */

  /* TODO Add methods for retrieving Torperf data files, GetTor stats
   * files, and bridge pool assignments from the descriptor store. */
}

