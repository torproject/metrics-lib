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

  /* Return the relay flags. */
  public SortedSet<String> getFlags();

  /* Return the Tor software version. */
  public String getVersion();

  /* Return the bandwidth weight line. */
  public String getBandwidth();

  /* Return the port summary line. */
  public String getPorts();
}

