/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.SortedMap;

public interface BridgeNetworkStatus extends Descriptor {

  /* Return the published time in milliseconds. */
  public long getPublishedMillis();

  /* Return status entries, one for each contained bridge. */
  public SortedMap<String, NetworkStatusEntry> getStatusEntries();
}

