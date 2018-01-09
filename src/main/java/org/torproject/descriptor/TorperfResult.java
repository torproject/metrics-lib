/* Copyright 2012--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;

/**
 * Contains performance measurement results from making simple HTTP
 * requests over the Tor network.
 *
 * <p>The performance measurement service Torperf publishes performance
 * data from making simple HTTP requests over the Tor network.  Torperf
 * uses a trivial SOCKS client to download files of various sizes over the
 * Tor network and notes how long substeps take.</p>
 *
 * @since 1.0.0
 */
public interface TorperfResult extends Descriptor {

  /**
   * Return all unrecognized keys together with their values, or null if
   * all keys were recognized.
   *
   * @since 1.2.0
   */
  public SortedMap<String, String> getUnrecognizedKeys();

  /**
   * Return the configured name of the data source.
   *
   * @since 1.0.0
   */
  public String getSource();

  /**
   * Return the configured file size in bytes.
   *
   * @since 1.0.0
   */
  public int getFileSize();

  /**
   * Return the time in milliseconds since the epoch when the connection
   * process started.
   *
   * @since 1.0.0
   */
  public long getStartMillis();

  /**
   * Return the time in milliseconds since the epoch when the socket was
   * created.
   *
   * @since 1.0.0
   */
  public long getSocketMillis();

  /**
   * Return the time in milliseconds since the epoch when the socket was
   * connected.
   *
   * @since 1.0.0
   */
  public long getConnectMillis();

  /**
   * Return the time in milliseconds since the epoch when SOCKS 5
   * authentication methods have been negotiated.
   *
   * @since 1.0.0
   */
  public long getNegotiateMillis();

  /**
   * Return the time in milliseconds since the epoch when the SOCKS
   * request was sent.
   *
   * @since 1.0.0
   */
  public long getRequestMillis();

  /**
   * Return the time in milliseconds since the epoch when the SOCKS
   * response was received.
   *
   * @since 1.0.0
   */
  public long getResponseMillis();

  /**
   * Return the time in milliseconds since the epoch when the HTTP
   * request was written.
   *
   * @since 1.0.0
   */
  public long getDataRequestMillis();

  /**
   * Return the time in milliseconds since the epoch when the first
   * response was received.
   *
   * @since 1.0.0
   */
  public long getDataResponseMillis();

  /**
   * Return the time in milliseconds since the epoch when the payload was
   * complete.
   *
   * @since 1.0.0
   */
  public long getDataCompleteMillis();

  /**
   * Return the total number of bytes written.
   *
   * @since 1.0.0
   */
  public int getWriteBytes();

  /**
   * Return the total number of bytes read.
   *
   * @since 1.0.0
   */
  public int getReadBytes();

  /**
   * Return whether the request timed out (as opposed to failing), or
   * null if the torperf line didn't contain that information.
   *
   * @since 1.0.0
   */
  public Boolean didTimeout();

  /**
   * Return the times in milliseconds since the epoch when {@code x%} of
   * expected bytes were read for {@code 0 <= x <= 100}, or null if the
   * torperf line didn't contain that information.
   *
   * @since 1.0.0
   */
  public SortedMap<Integer, Long> getDataPercentiles();

  /**
   * Return the time in milliseconds since the epoch when the circuit was
   * launched, or -1 if the torperf line didn't contain that
   * information.
   *
   * @since 1.0.0
   */
  public long getLaunchMillis();

  /**
   * Return the time in milliseconds since the epoch when the circuit was
   * used, or -1 if the torperf line didn't contain that information.
   *
   * @since 1.0.0
   */
  public long getUsedAtMillis();

  /**
   * Return a list of fingerprints of the relays in the circuit, or null
   * if the torperf line didn't contain that information.
   *
   * @since 1.0.0
   */
  public List<String> getPath();

  /**
   * Return a list of times in milliseconds since the epoch when circuit
   * hops were built, or null if the torperf line didn't contain that
   * information.
   *
   * @since 1.0.0
   */
  public List<Long> getBuildTimes();

  /**
   * Return the circuit build timeout that the Tor client used when
   * building this circuit, or -1 if the torperf line didn't contain that
   * information.
   *
   * @since 1.0.0
   */
  public long getTimeout();

  /**
   * Return the circuit build time quantile that the Tor client uses to
   * determine its circuit-build timeout, or -1 if the torperf line
   * didn't contain that information.
   *
   * @since 1.0.0
   */
  public double getQuantile();

  /**
   * Return the identifier of the circuit used for this measurement, or
   * -1 if the torperf line didn't contain that information.
   *
   * @since 1.0.0
   */
  public int getCircId();

  /**
   * Return the identifier of the stream used for this measurement, or -1
   * if the torperf line didn't contain that information.
   *
   * @since 1.0.0
   */
  public int getUsedBy();

  /**
   * Return the hostname, IP address, and port that the TGen client used to
   * connect to the local tor SOCKS port, formatted as
   * <code>hostname:ip:port</code>, which may be <code>"NULL:0.0.0.0:0"</code>
   * if TGen was not able to find this information or <code>null</code> if the
   * OnionPerf line didn't contain this information.
   *
   * @since 1.7.0
   */
  public String getEndpointLocal();

  /**
   * Return the hostname, IP address, and port that the TGen client used to
   * connect to the SOCKS proxy server that tor runs, formatted as
   * <code>hostname:ip:port</code>, which may be <code>"NULL:0.0.0.0:0"</code>
   * if TGen was not able to find this information or <code>null</code> if the
   * OnionPerf line didn't contain this information.
   *
   * @since 1.7.0
   */
  public String getEndpointProxy();

  /**
   * Return the hostname, IP address, and port that the TGen client used to
   * connect to the remote server, formatted as <code>hostname:ip:port</code>,
   * which may be <code>"NULL:0.0.0.0:0"</code> if TGen was not able to find
   * this information or <code>null</code> if the OnionPerf line didn't contain
   * this information.
   *
   * @since 1.7.0
   */
  public String getEndpointRemote();

  /**
   * Return the client machine hostname, which may be <code>"(NULL)"</code> if
   * the TGen client was not able to find this information or <code>null</code>
   * if the OnionPerf line didn't contain this information.
   *
   * @since 1.7.0
   */
  public String getHostnameLocal();

  /**
   * Return the server machine hostname, which may be <code>"(NULL)"</code> if
   * the TGen server was not able to find this information or <code>null</code>
   * if the OnionPerf line didn't contain this information.
   *
   * @since 1.7.0
   */
  public String getHostnameRemote();

  /**
   * Return the public IP address of the OnionPerf host obtained by connecting
   * to well-known servers and finding the IP address in the result, which may
   * be <code>"unknown"</code> if OnionPerf was not able to find this
   * information or <code>null</code> if the OnionPerf line didn't contain this
   * information.
   *
   * @since 1.7.0
   */
  public String getSourceAddress();
}

