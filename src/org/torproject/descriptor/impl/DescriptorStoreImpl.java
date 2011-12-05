/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.torproject.descriptor.BridgeNetworkStatus;
import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.DescriptorFile;
import org.torproject.descriptor.DescriptorStore;
import org.torproject.descriptor.DescriptorRequest;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;
import org.torproject.descriptor.RelayServerDescriptor;
import org.torproject.descriptor.RelayExtraInfoDescriptor;

public class DescriptorStoreImpl implements DescriptorStore {

  public boolean globalTimeoutHasExpired() {
    /* TODO Implement me. */
    return false;
  }

  public List<DescriptorRequest> getDescriptorRequests() {
    /* TODO Implement me. */
    return new ArrayList<DescriptorRequest>();
  }

  public List<DescriptorFile> getDescriptorFiles() {
    /* TODO Implement me. */
    return new ArrayList<DescriptorFile>();
  }

  public Set<RelayNetworkStatusConsensus>
      getAllRelayNetworkStatusConsensuses() {
    /* TODO Implement me. */
    return new HashSet<RelayNetworkStatusConsensus>();
  }

  public Set<RelayNetworkStatusVote> getAllRelayNetworkStatusVotes() {
    /* TODO Implement me. */
    return new HashSet<RelayNetworkStatusVote>();
  }

  public Set<RelayServerDescriptor> getAllRelayServerDescriptors() {
    /* TODO Implement me. */
    return new HashSet<RelayServerDescriptor>();
  }

  public Set<RelayExtraInfoDescriptor> getAllRelayExtraInfoDescriptors() {
    /* TODO Implement me. */
    return new HashSet<RelayExtraInfoDescriptor>();
  }

  public Set<BridgeNetworkStatus> getAllBridgeNetworkStatuses() {
    /* TODO Implement me. */
    return new HashSet<BridgeNetworkStatus>();
  }

  public Set<BridgeServerDescriptor> getAllBridgeServerDescriptors() {
    /* TODO Implement me. */
    return new HashSet<BridgeServerDescriptor>();
  }

  public Set<BridgeExtraInfoDescriptor>
      getAllBridgeExtraInfoDescriptors() {
    /* TODO Implement me. */
    return new HashSet<BridgeExtraInfoDescriptor>();
  }
}

