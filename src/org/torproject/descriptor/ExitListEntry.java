/* Copyright 2012--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

/**
 * Exit list entry containing results from a single exit scan.
 *
 * @since 1.0.0
 * @deprecated Superseded by {@link ExitList.Entry}.
 */
@Deprecated
public interface ExitListEntry extends ExitList.Entry {

  /**
   * Return the scanned relay's fingerprint, which is a SHA-1 digest of
   * the relays's public identity key, encoded as 40 upper-case
   * hexadecimal characters.
   *
   * @since 1.0.0
   */
  public String getFingerprint();

  /**
   * Return the time in milliseconds since the epoch when the scanned
   * relay's last known descriptor was published.
   *
   * @since 1.0.0
   */
  public long getPublishedMillis();

  /**
   * Return the time in milliseconds since the epoch when the network
   * status that this scan was based on was published.
   *
   * @since 1.0.0
   */
  public long getLastStatusMillis();

  /**
   * Return the IPv4 address in dotted-quad format that was determined in
   * the scan.
   *
   * @since 1.0.0
   */
  public String getExitAddress();

  /**
   * Return the scan time in milliseconds since the epoch.
   *
   * @since 1.0.0
   */
  public long getScanMillis();
}

