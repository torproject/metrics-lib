/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.SortedMap;

public interface BridgeNetworkStatus extends Descriptor {

  /* Return the published time in milliseconds. */
  public long getPublishedMillis();

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

  /* Return the minimum weighted time in seconds that this authority needs
   * to know about a relay before assigning the Guard flag, or -1 if the
   * authority doesn't report this information. */
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

  /* Return 1 if the authority has enough measured bandwidths that it'll
   * ignore the advertised bandwidth claims of routers without measured
   * bandwidth, 0 if not, or -1 if the authority doesn't report this
   * information. */
  public int getIgnoringAdvertisedBws();

  /* Return status entries, one for each contained bridge. */
  public SortedMap<String, NetworkStatusEntry> getStatusEntries();
}

