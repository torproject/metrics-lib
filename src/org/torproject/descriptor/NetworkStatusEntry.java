/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.SortedSet;

public interface NetworkStatusEntry {

  /* Return the raw status entry bytes. */
  public byte[] getStatusEntryBytes();

  /* Return the relay nickname. */
  public String getNickname();

  /* Return the relay fingerprint. */
  public String getFingerprint();

  /* Return the descriptor identity. */
  public String getDescriptor();

  /* Return the publication timestamp. */
  public long getPublishedMillis();

  /* Return the IP address. */
  public String getAddress();

  /* Return the ORPort. */
  public int getOrPort();

  /* Return the DirPort. */
  public int getDirPort();

  /* Return the relay flags or null if the status entry didn't contain any
   * relay flags. */
  public SortedSet<String> getFlags();

  /* Return the Tor software version or null if the status entry didn't
   * contain a version line. */
  public String getVersion();

  /* Return the bandwidth weight or -1L if the status entry didn't
   * contain a bandwidth line. */
  public long getBandwidth();

  /* Return the measured bandwidth or -1L if the status entry didn't
   * contain a bandwidth line or didn't contain a Measured= keyword in its
   * bandwidth line. */
  public long getMeasured();

  /* Return the default policy of the port summary or null if the status
   * entry didn't contain a port summary line. */
  public String getDefaultPolicy();

  /* Return the port list of the port summary or null if the status entry
   * didn't contain a port summary line. */
  public String getPortList();
}

