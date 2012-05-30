/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;

public interface TorperfResult extends Descriptor {

  /* Return the configured name of the data source. */
  public String getSource();

  /* Return the configured file size in bytes. */
  public int getFileSize();

  /* Return the time when the connection process starts. */
  public long getStartMillis();

  /* Return the time when the socket was created. */
  public long getSocketMillis();

  /* Return the time when the socket was connected. */
  public long getConnectMillis();

  /* Return the time when SOCKS 5 authentication methods have been
   * negotiated. */
  public long getNegotiateMillis();

  /* Return the time when the SOCKS request was sent. */
  public long getRequestMillis();

  /* Return the time when the SOCKS response was received. */
  public long getResponseMillis();

  /* Return the time when the HTTP request was written. */
  public long getDataRequestMillis();

  /* Return the time when the first response was received. */
  public long getDataResponseMillis();

  /* Return the time when the payload was complete. */
  public long getDataCompleteMillis();

  /* Return the total number of bytes written. */
  public int getWriteBytes();

  /* Return the total number of bytes read. */
  public int getReadBytes();

  /* Return whether the request timed out (as opposed to failing), or null
   * if the torperf line didn't contain that information. */
  public Boolean didTimeout();

  /* Return the times when x% of expected bytes were read for x = { 10,
   * 20, 30, 40, 50, 60, 70, 80, 90 }, or null if the torperf line didn't
   * contain that information. */
  public SortedMap<Integer, Long> getDataPercentiles();

  /* Return the time when the circuit was launched, or -1 if the torperf
   * line didn't contain that information. */
  public long getLaunchMillis();

  /* Return the time when the circuit was used, or -1 if the torperf line
   * didn't contain that information. */
  public long getUsedAtMillis();

  /* Return a list of fingerprints of the relays in the circuit, or null
   * if the torperf line didn't contain that information. */
  public List<String> getPath();

  /* Return a list of times in millis when circuit hops were built, or
   * null if the torperf line didn't contain that information. */
  public List<Long> getBuildTimes();

  /* Return the circuit build timeout that the Tor client used when
   * building this circuit, or -1 if the torperf line didn't contain that
   * information. */
  public long getTimeout();

  /* Return the circuit build time quantile that the Tor client uses to
   * determine its circuit-build timeout, or -1.0 if the torperf line
   * didn't contain that information. */
  public double getQuantile();

  /* Return the identifier of the circuit used for this measurement, or -1
   * if the torperf line didn't contain that information. */
  public int getCircId();

  /* Return the identifier of the stream used for this measurement, or -1
   * if the torperf line didn't contain that information. */
  public int getUsedBy();
}

