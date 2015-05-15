/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.SortedMap;

/* Contains the bandwidth history of a relay or bridge. */
public interface BandwidthHistory {

  /* Return the original bandwidth history line as contained in the
   * descriptor, possibly prefixed with "opt ". */
  public String getLine();

  /* Return the end of the most recent interval in millis. */
  public long getHistoryEndMillis();

  /* Return the interval length in seconds, which is typically 900 seconds
   * or 15 minutes. */
  public long getIntervalLength();

  /* Return the (possibly empty) bandwidth history with map keys being
   * interval ends in millis and map values being number of bytes used in
   * the interval, ordered from oldest to newest interval. */
  public SortedMap<Long, Long> getBandwidthValues();
}

